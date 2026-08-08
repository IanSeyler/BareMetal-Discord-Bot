// discord_bot.c - a Discord bot that watches one channel and replies
// with a Pig Latin translation of any human message that directly
// @mentions it.
//
// DISCORD_BOT_TOKEN and DISCORD_CHANNEL_ID variables must be set below.
//
// BareMetal build instructions:
// git clone https://github.com/ReturnInfinity/BareMetal-App
// cp discord_bot.c BareMetal-App/
// cd BareMetal-App
// ./setup.sh
// ./1-build.sh discord_bot.c
// ./2-run.sh
// ./3-upload.sh - optional to upload to BareMetal Cloud
//
// This is also a valid *nix program of course.
//
// TODO:
// Polling, not the Gateway: a "real" Discord bot normally keeps a
// persistent WebSocket open to Discord's Gateway and gets pushed
// MESSAGE_CREATE events as they happen. That's not available here -
// BareMetal-App/port/curl_port/curl_config.h has
// `#define CURL_DISABLE_WEBSOCKETS 1` (see its file header for why:
// this port's curl build only carries plain HTTP/HTTPS).
// So instead this polls the plain REST endpoint GET
// /channels/{id}/messages every POLL_INTERVAL_SECS, using `after`
// to ask only for messages newer than the last one it already handled,
// and replies via POST /channels/{id}/messages - both ordinary HTTPS
// requests through libcurl, same as wiki_discord.c's webhook POST (see
// that file for the baseline this is built on: same net_shim.c sockets,
// same vendored mbedTLS backend, same curl_easy_reset()-between-requests
// pattern since one CURL* handle is reused for every call here).
//
// Discord Setup: create an application + bot at
// https://discord.com/developers/applications, copy its token into
// DISCORD_BOT_TOKEN below, invite it to a server with the "bot" scope
// and the Read Messages/View Channel + Send Messages permissions, and
// turn on the "Message Content Intent" toggle on the Bot tab - without
// it Discord redacts the `content` field (returns "") on every message
// this bot didn't send itself, for both Gateway events *and* this REST
// endpoint. Then set DISCORD_CHANNEL_ID to the target channel's ID
// (right-click it in Discord with Developer Mode enabled -> Copy
// Channel ID). Both are per-bot secrets/identifiers, not something to
// hardcode into a shared/example file, so they're intentionally blank
// below - main() refuses to run with either left empty.
//
// Same certificate-verification stance as wiki_discord.c/curltest.c,
// and for the same reason (no CA store is vendored on this port):
// CURLOPT_SSL_VERIFYPEER/VERIFYHOST are both off. TLS still buys
// confidentiality on the wire, just not server-identity assurance -
// acceptable for hitting one known-good public endpoint, but the bot
// token is a bearer credential regardless, so treat it like a password.
//
// No message loss across polls, only latency: `after` always advances
// to the newest message id this bot has seen, so a burst bigger than
// MAX_MSG_OBJS just gets finished across the next poll or two rather
// than dropping anything.
//
// @mention gating: main() fetches this bot's own snowflake once at
// startup via GET /users/@me, then mentions_bot() checks each message's
// raw content for a literal "<@id>" or "<@!id>" (the two forms Discord
// itself renders a user mention as - "<@!id>" is the older
// nickname-mention form some clients still send). Everything else -
// plain messages, @everyone/@here, role mentions, replies that don't
// also type the mention - is ignored. Requires the bot's token to
// still be valid at startup, since a failed /users/@me lookup means it
// can never recognize its own mentions.
//
// JSON handling is hand-rolled (see json_extract_string()/
// json_extract_object()/split_json_objects() below), not a real parser
// - just "good enough for this shape of input".
// It does track string/escape state and brace/bracket depth throughout,
// though, and not just so message content's raw '{'/'}'/',' bytes can't
// mis-split split_json_objects()'s array scan:
// json_extract_string()/json_extract_object() route through
// find_top_level() so they only ever match a key belonging to the
// object they were handed, not one nested inside "mentions", "author",
// or (a reply's) "referenced_message" - see find_top_level()'s comment
// for the bug that shape of mismatch actually caused here. Nothing here
// validates the response is well-formed JSON beyond that.
//
// Pig Latin rules used below (pig_latin_word()): a leading vowel run
// gets "way" appended; otherwise the leading consonant cluster (a
// trailing "qu" counts as part of it, so "queen" -> "eenquay" not
// "ueenqay") moves to the end plus "ay"; a word with no vowels at all
// just gets "ay" appended. Only the first letter's case survives in
// the output (the rest is lowercased) - ALL-CAPS input comes back
// Titlecase, which is a known, accepted simplification. Punctuation/
// digits attached to a word (contractions, trailing commas, ...) are
// copied through untouched between letter runs, so e.g. "don't" pig
// latinates each half separately ("don" and "t") rather than treating
// the apostrophe as a letter. Discord mentions/channels/emoji
// (<@id>, <#id>, <:name:id>, <a:name:id>) and http(s):// URLs are
// passed through as whole tokens, unmangled - translating those would
// break a real mention/ping or a working link.
//
// All buffers are static, fixed-size, not malloc'd - this is meant for
// a memory-constrained microVM. Tested successfully on a 4MiB microVM.

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#define DISCORD_API_BASE    "https://discord.com/api/v10"

// The values below must be set
#define DISCORD_BOT_TOKEN   ""
#define DISCORD_CHANNEL_ID  ""

#define USER_AGENT "BareMetal-Discord-Bot (https://github.com/IanSeyler/BareMetal-Discord-Bot, 1.0)"

#define POLL_INTERVAL_SECS 3
#define MAX_MSG_OBJS       10 // must match the `limit` query param used below

#define MSG_BUF_SIZE       (32 * 1024) // GET /messages response (up to MAX_MSG_OBJS messages)
#define OBJ_BUF_SIZE       4096        // one message object, copied out of msg_buf
#define AUTHOR_BUF_SIZE    1024        // one message's nested "author" object
#define CONTENT_BUF_SIZE   2048        // one message's "content" field (Discord caps it at 2000)
#define REPLY_BUF_SIZE     (8 * 1024)  // pig-latinated reply, before truncation (see CONTENT_MAX)
#define PAYLOAD_BUF_SIZE   (8 * 1024)  // JSON POST body for the reply
#define POST_RESP_SIZE     4096
#define CONTENT_MAX        1900 // Discord hard-caps message content at 2000 UTF-8 chars; leave headroom

struct membuf {
	char *data;
	size_t cap;
	size_t len;
};

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct membuf *mb = userdata;
	size_t n = size * nmemb;

	size_t room = mb->cap - 1 - mb->len;
	size_t copy = n < room ? n : room;
	memcpy(mb->data + mb->len, ptr, copy);
	mb->len += copy;
	mb->data[mb->len] = '\0';

	return n; // report all of n "written" even on overflow - see curltest.c's write_cb
}

// libcurl setup shared by every request below.
static void curl_common_opts(CURL *h)
{
	curl_easy_setopt(h, CURLOPT_USERAGENT, USER_AGENT);
	curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L); // see file header
	curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(h, CURLOPT_TIMEOUT, 30L); // matches net_shim.c's own per-call cap
}

// GETs url with the given "Authorization: Bot ..." header into mb.
// Returns the HTTP status, or -1 on a transport-level failure (mb still
// holds whatever partial body, if any, curl delivered before that).
static long http_get(CURL *h, const char *url, const char *auth_header, struct membuf *mb)
{
	mb->len = 0;
	mb->data[0] = '\0';

	curl_easy_reset(h); // undoes any leftover POST state from a previous call on this handle
	curl_common_opts(h);
	curl_easy_setopt(h, CURLOPT_URL, url);
	curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(h, CURLOPT_WRITEDATA, mb);

	struct curl_slist *headers = curl_slist_append(NULL, auth_header);
	curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers);

	CURLcode res = curl_easy_perform(h);
	long status = 0;
	curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
	curl_slist_free_all(headers);

	if (res != CURLE_OK) {
		fprintf(stderr, "GET %s failed: %s\n", url, curl_easy_strerror(res));
		return -1;
	}
	return status;
}

// POSTs a JSON payload (paylen bytes) to url with the given auth header
// into mb. Same return convention as http_get().
static long http_post(CURL *h, const char *url, const char *auth_header,
		       const char *payload, size_t paylen, struct membuf *mb)
{
	mb->len = 0;
	mb->data[0] = '\0';

	curl_easy_reset(h);
	curl_common_opts(h);
	curl_easy_setopt(h, CURLOPT_URL, url);
	curl_easy_setopt(h, CURLOPT_POST, 1L);
	curl_easy_setopt(h, CURLOPT_POSTFIELDS, payload);
	curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, (long)paylen);
	curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(h, CURLOPT_WRITEDATA, mb);

	struct curl_slist *headers = curl_slist_append(NULL, auth_header);
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers);

	CURLcode res = curl_easy_perform(h);
	long status = 0;
	curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
	curl_slist_free_all(headers);

	if (res != CURLE_OK) {
		fprintf(stderr, "POST %s failed: %s\n", url, curl_easy_strerror(res));
		return -1;
	}
	return status;
}

// Finds the first occurrence of pat (a literal like "\"id\":\"") within
// json that starts at brace/bracket depth 1 - i.e. a key belonging to
// json's own outermost object, not one nested inside some array/object
// value. A message that's itself a reply embeds the whole replied-to
// message under "referenced_message" (own "id"/"content"/"author" and
// all), and an @mention embeds the mentioned user's object (own "id")
// under "mentions" - Discord's JSON key order isn't documented or
// guaranteed, so a depth-blind strstr() can match one of those instead
// of the outer message's own field. (Concretely: this is why an early
// version of this extractor sometimes read a mentioned user's id as if
// it were the message id.) Returns NULL if pat never occurs at depth 1.
static const char *find_top_level(const char *json, const char *pat)
{
	size_t patlen = strlen(pat);
	int depth = 0, in_string = 0, escape = 0;

	for (const char *p = json; *p; p++) {
		char c = *p;
		if (in_string) {
			if (escape)
				escape = 0;
			else if (c == '\\')
				escape = 1;
			else if (c == '"')
				in_string = 0;
			continue;
		}
		if (c == '"') {
			if (depth == 1 && strncmp(p, pat, patlen) == 0)
				return p;
			in_string = 1;
			continue;
		}
		if (c == '{' || c == '[')
			depth++;
		else if (c == '}' || c == ']')
			depth--;
	}
	return NULL;
}

// Extracts the value of json's own top-level "key":"..." string field
// (see find_top_level() - not just the first occurrence anywhere in
// json) into out. Decodes \" \\ \/ \n \r \t; drops \uXXXX escapes and
// any other backslash escape rather than decoding them. Returns 1 if
// the key was found, 0 otherwise (out is left empty).
static int json_extract_string(const char *json, const char *key, char *out, size_t outsz)
{
	char pat[64];
	snprintf(pat, sizeof(pat), "\"%s\":\"", key);

	out[0] = '\0';
	const char *p = find_top_level(json, pat);
	if (!p)
		return 0;
	p += strlen(pat);

	size_t n = 0;
	while (*p && *p != '"' && n + 1 < outsz) {
		if (*p == '\\' && p[1]) {
			p++;
			switch (*p) {
			case 'n': out[n++] = '\n'; break;
			case 'r': out[n++] = '\r'; break;
			case 't': out[n++] = '\t'; break;
			case '"': out[n++] = '"'; break;
			case '\\': out[n++] = '\\'; break;
			case '/': out[n++] = '/'; break;
			case 'u':
				for (int i = 0; i < 4 && p[1]; i++)
					p++;
				break;
			default:
				break; // unknown escape - drop it
			}
			p++;
		} else {
			out[n++] = *p++;
		}
	}
	out[n] = '\0';
	return 1;
}

// Like json_extract_string(), but for a "key": <number> field (no
// quotes, e.g. rate-limit responses' "retry_after": 0.418). Returns 0.0
// if key isn't found.
static double json_extract_number(const char *json, const char *key)
{
	char pat[64];
	snprintf(pat, sizeof(pat), "\"%s\":", key);

	const char *p = strstr(json, pat);
	if (!p)
		return 0.0;
	return atof(p + strlen(pat));
}

// Extracts the nested object value of json's own top-level "key":{...}
// (see find_top_level()) into out, including the enclosing braces.
// Tracks string/escape state and brace depth while copying so a
// '{'/'}'/',' inside a nested string doesn't confuse the boundary.
// Returns 1 if the key was found, 0 otherwise (out is left empty).
// Used here to pull a message's own "author" object out so its "bot"
// field can be checked without matching a "referenced_message"'s
// author (or any other nested "author") first.
static int json_extract_object(const char *json, const char *key, char *out, size_t outsz)
{
	char pat[64];
	snprintf(pat, sizeof(pat), "\"%s\":{", key);

	out[0] = '\0';
	const char *p = find_top_level(json, pat);
	if (!p)
		return 0;
	p += strlen(pat) - 1; // back up onto the '{' itself

	int depth = 0, in_string = 0, escape = 0;
	size_t n = 0;
	for (; *p; p++) {
		char c = *p;
		if (n + 1 < outsz)
			out[n++] = c;

		if (in_string) {
			if (escape)
				escape = 0;
			else if (c == '\\')
				escape = 1;
			else if (c == '"')
				in_string = 0;
			continue;
		}
		if (c == '"')
			in_string = 1;
		else if (c == '{')
			depth++;
		else if (c == '}') {
			depth--;
			if (depth == 0)
				break;
		}
	}
	out[n] = '\0';
	return 1;
}

// Splits the top-level array in json into its object elements: starts[i]
// points at each element's opening '{' within json, lens[i] is its
// length through the matching closing '}'. Tracks string/escape state
// and brace depth (see json_extract_object()) so message content
// containing raw '{'/'}'/'"' bytes can't mis-split it. Stops early if
// max_objs is reached, or silently drops a trailing object that's cut
// off mid-way (e.g. msg_buf filled up) since it has no matching '}'.
// Returns the number of complete objects found.
static int split_json_objects(const char *json, const char **starts, size_t *lens, int max_objs)
{
	int count = 0;
	int depth = 0, in_string = 0, escape = 0;
	const char *obj_start = NULL;

	for (const char *p = json; *p; p++) {
		char c = *p;

		if (in_string) {
			if (escape)
				escape = 0;
			else if (c == '\\')
				escape = 1;
			else if (c == '"')
				in_string = 0;
			continue;
		}
		if (c == '"') {
			in_string = 1;
			continue;
		}
		if (c == '{') {
			if (depth == 0)
				obj_start = p;
			depth++;
		} else if (c == '}') {
			depth--;
			if (depth == 0 && obj_start && count < max_objs) {
				starts[count] = obj_start;
				lens[count] = (size_t)(p - obj_start + 1);
				count++;
				obj_start = NULL;
			}
		}
	}
	return count;
}

// Discord snowflake IDs are decimal strings that only grow in digit
// count over time (they're really 64-bit integers) - compare digit
// count first, then lexicographically, rather than as numbers neither
// atoll() nor strtoull() can safely round-trip at this width.
static int snowflake_gt(const char *a, const char *b)
{
	size_t la = strlen(a), lb = strlen(b);
	if (la != lb)
		return la > lb;
	return strcmp(a, b) > 0;
}

// True if content literally contains a mention of bot_id, in either
// form Discord itself writes a user mention as: "<@id>" or the older
// nickname-mention form "<@!id>". See file header for why this (not
// the message's "mentions" array) is what gates a reply.
static int mentions_bot(const char *content, const char *bot_id)
{
	char pat[40], pat_nick[40];
	snprintf(pat, sizeof(pat), "<@%s>", bot_id);
	snprintf(pat_nick, sizeof(pat_nick), "<@!%s>", bot_id);
	return strstr(content, pat) != NULL || strstr(content, pat_nick) != NULL;
}

static int is_vowel(char c)
{
	c = (char)tolower((unsigned char)c);
	return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u';
}

// Pig-latinates one maximal run of ASCII letters (word, len bytes long,
// no digits/punctuation) into out. See file header for the rules and
// their simplifications. Runs longer than 63 bytes are truncated before
// conversion (a real word is never remotely that long).
static void pig_latin_word(const char *word, size_t len, char *out, size_t outsz)
{
	char lower[64];
	size_t n = len < sizeof(lower) - 1 ? len : sizeof(lower) - 1;
	for (size_t i = 0; i < n; i++)
		lower[i] = (char)tolower((unsigned char)word[i]);
	lower[n] = '\0';

	size_t split;
	if (n == 0) {
		split = 0;
	} else if (is_vowel(lower[0])) {
		split = 0;
	} else {
		split = 1;
		while (split < n && !is_vowel(lower[split]))
			split++;
		if (split < n && lower[split - 1] == 'q' && lower[split] == 'u')
			split++; // keep "qu" together: "queen" -> "eenquay", not "ueenqay"
	}

	int cap = n > 0 && isupper((unsigned char)word[0]);
	size_t pos = 0;
	for (size_t i = split; i < n && pos + 1 < outsz; i++)
		out[pos++] = lower[i];
	for (size_t i = 0; i < split && pos + 1 < outsz; i++)
		out[pos++] = lower[i];
	const char *suffix = (split == 0) ? "way" : "ay";
	for (; *suffix && pos + 1 < outsz; suffix++)
		out[pos++] = *suffix;
	out[pos] = '\0';

	if (cap && pos > 0)
		out[0] = (char)toupper((unsigned char)out[0]);
}

// Pig-latinates text into out, word by word, preserving whitespace and
// punctuation and passing Discord mentions/channels/emoji and http(s)
// URLs through untouched. See file header for the full rule set.
static void pig_latin_text(const char *text, char *out, size_t outsz)
{
	size_t pos = 0;
	const char *p = text;

	while (*p && pos + 1 < outsz) {
		if (isspace((unsigned char)*p)) {
			out[pos++] = *p++;
			continue;
		}

		const char *tok = p;
		while (*p && !isspace((unsigned char)*p))
			p++;
		size_t tok_len = (size_t)(p - tok);

		int passthrough =
			(tok_len >= 2 && tok[0] == '<' && tok[tok_len - 1] == '>') ||
			(tok_len > 7 && strncmp(tok, "http://", 7) == 0) ||
			(tok_len > 8 && strncmp(tok, "https://", 8) == 0);

		if (passthrough) {
			for (size_t i = 0; i < tok_len && pos + 1 < outsz; i++)
				out[pos++] = tok[i];
			continue;
		}

		size_t i = 0;
		while (i < tok_len && pos + 1 < outsz) {
			if (isalpha((unsigned char)tok[i])) {
				size_t run = 0;
				while (i + run < tok_len && isalpha((unsigned char)tok[i + run]))
					run++;
				char word[96];
				pig_latin_word(tok + i, run, word, sizeof(word));
				for (char *w = word; *w && pos + 1 < outsz; w++)
					out[pos++] = *w;
				i += run;
			} else {
				out[pos++] = tok[i++];
			}
		}
	}
	out[pos] = '\0';
}

// Appends s to out (a nul-terminated buffer of size outsz, *pos bytes
// already used), JSON-escaping it as it goes. Bare '\r' and other
// control characters below 0x20 are dropped rather than escaped.
static void json_escape_append(char *out, size_t outsz, size_t *pos, const char *s)
{
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\') {
			if (*pos + 2 >= outsz)
				break;
			out[(*pos)++] = '\\';
			out[(*pos)++] = c;
		} else if (c == '\n') {
			if (*pos + 2 >= outsz)
				break;
			out[(*pos)++] = '\\';
			out[(*pos)++] = 'n';
		} else if (c == '\t') {
			if (*pos + 2 >= outsz)
				break;
			out[(*pos)++] = '\\';
			out[(*pos)++] = 't';
		} else if (c < 0x20) {
			// drop other control chars, including bare '\r'
		} else {
			if (*pos + 1 >= outsz)
				break;
			out[(*pos)++] = c;
		}
	}
	out[*pos] = '\0';
}

// If s is longer than maxlen bytes, trims it back to at most maxlen,
// stepping back further if needed so the cut doesn't land inside a
// multi-byte UTF-8 sequence (a continuation byte has its top two bits
// as "10"). Does not otherwise validate that s is well-formed UTF-8.
static void truncate_utf8(char *s, size_t maxlen)
{
	size_t len = strlen(s);
	if (len <= maxlen)
		return;

	size_t cut = maxlen;
	while (cut > 0 && (s[cut] & 0xC0) == 0x80)
		cut--;

	s[cut] = '\0';
}

// Sleeps out a 429 response's Retry-After (rounded up, minimum 1s).
// resp_body is the JSON error body, which carries a "retry_after"
// field in seconds; falls back to 1s if it's missing or unparseable.
static void wait_out_rate_limit(const char *resp_body)
{
	double retry = json_extract_number(resp_body, "retry_after");
	int secs = (int)(retry + 1.0);
	if (secs < 1)
		secs = 1;
	fprintf(stderr, "rate limited, sleeping %ds\n", secs);
	sleep((unsigned)secs);
}

int main(void)
{
	printf("BareMetal discord_bot - polls a channel, replies in Pig Latin\n\n");

	if (DISCORD_BOT_TOKEN[0] == '\0' || DISCORD_CHANNEL_ID[0] == '\0') {
		fprintf(stderr, "error: DISCORD_BOT_TOKEN and/or DISCORD_CHANNEL_ID is empty - "
				"edit discord_bot.c and set both before building. See the file "
				"header for how to create a bot, invite it, and find a channel "
				"ID.\n");
		return 1;
	}

	curl_global_init(CURL_GLOBAL_DEFAULT);

	CURL *h = curl_easy_init();
	if (!h) {
		fprintf(stderr, "curl_easy_init() failed\n");
		curl_global_cleanup();
		return 1;
	}

	char auth_header[128];
	snprintf(auth_header, sizeof(auth_header), "Authorization: Bot %s", DISCORD_BOT_TOKEN);

	char get_url[256];
	snprintf(get_url, sizeof(get_url), "%s/channels/%s/messages", DISCORD_API_BASE, DISCORD_CHANNEL_ID);
	char post_url[256];
	snprintf(post_url, sizeof(post_url), "%s/channels/%s/messages", DISCORD_API_BASE, DISCORD_CHANNEL_ID);

	static char msg_buf[MSG_BUF_SIZE];
	struct membuf msg_mb = { msg_buf, sizeof(msg_buf), 0 };

	// This bot's own snowflake, needed to recognize "<@this id>" in a
	// message's content - see mentions_bot()/file header.
	char bot_id[32] = "";
	{
		char url[128];
		snprintf(url, sizeof(url), "%s/users/@me", DISCORD_API_BASE);
		long status = http_get(h, url, auth_header, &msg_mb);
		if (status == 200)
			json_extract_string(msg_buf, "id", bot_id, sizeof(bot_id));
		if (bot_id[0] == '\0') {
			fprintf(stderr, "error: couldn't fetch this bot's own user id from GET "
					"/users/@me (HTTP %ld) - can't tell when it's been @mentioned "
					"without it. Check DISCORD_BOT_TOKEN.\n", status);
			curl_easy_cleanup(h);
			curl_global_cleanup();
			return 1;
		}
	}

	char last_id[32] = "0"; // "0" sorts below every real snowflake

	// Seed last_id with whatever's already the newest message in the
	// channel, so the bot reacts only to messages sent after it
	// starts, not the whole channel backlog.
	{
		char url[300];
		snprintf(url, sizeof(url), "%s?limit=1", get_url);
		long status = http_get(h, url, auth_header, &msg_mb);
		if (status == 200) {
			const char *starts[1];
			size_t lens[1];
			int n = split_json_objects(msg_buf, starts, lens, 1);
			if (n == 1) {
				static char objbuf[OBJ_BUF_SIZE];
				size_t cl = lens[0] < sizeof(objbuf) - 1 ? lens[0] : sizeof(objbuf) - 1;
				memcpy(objbuf, starts[0], cl);
				objbuf[cl] = '\0';
				json_extract_string(objbuf, "id", last_id, sizeof(last_id));
			}
		} else {
			fprintf(stderr, "warning: couldn't seed the last message id (HTTP %ld) - "
					"starting from scratch, which may replay recent history\n", status);
		}
	}

	printf("watching channel %s as user %s, starting after message id %s\n\n",
	       DISCORD_CHANNEL_ID, bot_id, last_id);

	for (;;) {
		char url[300];
		snprintf(url, sizeof(url), "%s?limit=%d&after=%s", get_url, MAX_MSG_OBJS, last_id);

		long status = http_get(h, url, auth_header, &msg_mb);

		if (status == 429) {
			wait_out_rate_limit(msg_mb.data);
			continue;
		}
		if (status != 200) {
			fprintf(stderr, "GET messages failed (HTTP %ld), retrying in %ds\n",
				status, POLL_INTERVAL_SECS);
			sleep(POLL_INTERVAL_SECS);
			continue;
		}

		const char *starts[MAX_MSG_OBJS];
		size_t lens[MAX_MSG_OBJS];
		int n = split_json_objects(msg_buf, starts, lens, MAX_MSG_OBJS);

		// `after` returns messages oldest-first, but track the max id
		// seen regardless of order rather than assuming that holds.
		for (int i = 0; i < n; i++) {
			static char objbuf[OBJ_BUF_SIZE];
			size_t cl = lens[i] < sizeof(objbuf) - 1 ? lens[i] : sizeof(objbuf) - 1;
			memcpy(objbuf, starts[i], cl);
			objbuf[cl] = '\0';

			char id[32];
			if (!json_extract_string(objbuf, "id", id, sizeof(id)))
				continue;
			if (snowflake_gt(id, last_id))
				strcpy(last_id, id);

			static char author[AUTHOR_BUF_SIZE];
			json_extract_object(objbuf, "author", author, sizeof(author));
			if (strstr(author, "\"bot\":true"))
				continue; // skip other bots and our own replies - avoids echo loops

			static char content[CONTENT_BUF_SIZE];
			if (!json_extract_string(objbuf, "content", content, sizeof(content)) || content[0] == '\0')
				continue; // attachment/embed-only message (or Message Content Intent is off)

			if (!mentions_bot(content, bot_id))
				continue; // only reply when directly @mentioned - see file header

			static char reply[REPLY_BUF_SIZE];
			pig_latin_text(content, reply, sizeof(reply));

			int truncated = strlen(reply) > CONTENT_MAX - 3;
			truncate_utf8(reply, truncated ? CONTENT_MAX - 3 : CONTENT_MAX);
			if (truncated)
				strcat(reply, "...");

			static char payload[PAYLOAD_BUF_SIZE];
			size_t pos = 0;
			snprintf(payload, sizeof(payload), "{\"content\":\"");
			pos = strlen(payload);
			json_escape_append(payload, sizeof(payload), &pos, reply);

			char tail[64];
			int tlen = snprintf(tail, sizeof(tail),
				"\",\"message_reference\":{\"message_id\":\"%s\"}}", id);
			if (tlen > 0 && pos + (size_t)tlen < sizeof(payload)) {
				memcpy(payload + pos, tail, (size_t)tlen + 1);
				pos += (size_t)tlen;
			}

			static char post_resp[POST_RESP_SIZE];
			struct membuf post_mb = { post_resp, sizeof(post_resp), 0 };

			long pstatus = http_post(h, post_url, auth_header, payload, pos, &post_mb);
			if (pstatus == 429) {
				wait_out_rate_limit(post_resp);
			} else if (pstatus < 200 || pstatus >= 300) {
				fprintf(stderr, "reply to %s failed (HTTP %ld): %.*s\n",
					id, pstatus, (int)post_mb.len, post_resp);
			} else {
				printf("[%s] %s -> %s\n", id, content, reply);
			}
		}

		sleep(POLL_INTERVAL_SECS);
	}

	curl_easy_cleanup(h);
	curl_global_cleanup();
	return 0;
}
