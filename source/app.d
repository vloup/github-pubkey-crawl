import std.algorithm : joiner;
import std.concurrency;
import std.conv;
import std.file: exists, getSize, remove;
import std.json;
import std.net.curl;
import std.parallelism : parallel;
import std.stdio;
import std.string;

/**
 * Main entry point.
 * Params:
 *   args = command line arguments
 * Returns:
 *   the global return status code
 */
int main(string[] args)
{
	import std.getopt : getopt;

	string filename = "github-pubkey.csv";
	enum credcache = "login-info";
	size_t pubkeyWorkerNum = 10;
	ulong id = 0;
	bool askPassword = false;
	bool crawlGPGKeys = false;

	try {
		const auto help = getopt(args, "output|o", &filename,
				"id|i", &id,
				"ask-password", &askPassword,
				"gpg", &crawlGPGKeys,
				"worker|w", &pubkeyWorkerNum);

		if (help.helpWanted) {
			printHelp();
			return 0;
		}
	} catch (ConvException ce) {
		stderr.writeln("[ERROR] Could not parse arguments.");
		printHelp();
		return 1;
	}

	if (id == 0) {
		writeln("Finding last user id crawled.");
		try {
			id = getLastId(filename);
		} catch (Exception e) {
			stderr.writeln(e.msg);
			return 2;
		}
	}
	writeln("Starting with user id ", id, ".");

	HTTP conn = getAuthentication(askPassword, credcache);

	writeln("Spawning pubkey workers.");
	Tid print = spawn(&printworker, thisTid, filename);
	Tid[] pubkey = new Tid[pubkeyWorkerNum];
	for (size_t i = 0; i < pubkeyWorkerNum; i++) {
		pubkey[i] = spawn(&pubkeyworker, thisTid, print, crawlGPGKeys);
	}

	writeln("Starting main user worker.");
	const int retcode = userworker(pubkey, conn, id);
	stdout.flush();

	/* ensure correct termination of children threads */
	writeln("Waiting for other threads to finish.");
	for (size_t i = 0; i < pubkey.length; i++) {
		send(pubkey[i], "FIN");
		receiveOnly!string();
	}

	stdout.flush();
	send(print, "FIN");
	receiveOnly!string();

	if ((retcode == 0 || retcode == -1) && exists(credcache)) {
		remove(credcache);
	}

	return retcode;
}

/**
 * Print the crawler's command line options.
 */
void printHelp()
{
	writeln("Usage: github-pubkey-crawl [options...]");
	writeln("Options:");
	writeln(" -o, --output FILE      Specify an output file.");
	writeln(" -i, --index ID         Specify a starting id to crawl.");
	writeln("                        A negative value (including 0) will continue the previous crawl if it can.");
	writeln("                        If no other crawl were done previously, it will start from the beginning,");
	writeln("     --ask-password     Do not cache the password on disk in the «login-info» file and prompt for it");
	writeln("                        instead.");
	writeln("     --gpg              (Experimental) Fetch PGP keys instead of SSH keys.");
	writeln(" -w, --worker AMOUNT    Specify the amount of subworkers for the key gathering task.");
	writeln(" -h, --help             Display this help.");
}

/**
 * Get the last user id from the output file.
 * Params:
 *   filename = file we will look the last id into.
 * Returns:
 *   the last user id of the file
 */
ulong getLastId(string filename)
{
	import core.stdc.config : c_long;
	import core.stdc.stdio : fclose, fgets, fopen, fseek, ftell;
	import core.stdc.stdlib : calloc, free;
	import std.csv : csvReader;
	import std.typecons : Tuple;

	enum ERR_OPEN = "[ERROR] Failed to open file.";
	enum ERR_SEEK = "[ERROR] Failed to seek in file.";
	enum ERR_CALLOC = "[ERROR] Failed to calloc memory.";
	enum ERR_FGETS = "[ERROR] Failed to fgets in file.";

	if (!exists(filename)) {
		return 0;
	}

	/* empty file */
	if (getSize(filename) == 0) {
		return 0;
	}

	int ret = 0;

	FILE* fd = fopen(filename.toStringz, "r");
	if (!fd) {
		throw new Exception(ERR_OPEN);
	}

	/* EOF */
	ret = fseek(fd, 0, SEEK_END);
	if (ret != 0) {
		fclose(fd);
		throw new Exception(ERR_SEEK);
	}

	c_long end = ftell(fd);

	/* last \n */
	ret = fseek(fd, -1, SEEK_CUR);
	if (ret != 0 || ftell(fd) == 0) {
		fclose(fd);
		throw new Exception(ERR_SEEK);
	}

	/*
	 * Backtrack up to the previous \n.
	 * Also, make sure we are being able to seek one back.
	 */
	int c = -1;
	while (c != '\n' && ftell(fd) > 0) {
		ret = fseek(fd, -1, SEEK_CUR);
		if (ret != 0) {
			fclose(fd);
			throw new Exception(ERR_SEEK);
		}

		c = fgetc(fd);

		ret = fseek(fd, -1, SEEK_CUR);
		if (ret != 0) {
			fclose(fd);
			throw new Exception(ERR_SEEK);
		}
	}

	/* are we in the middle of the file or we found the start? */
	if (ftell(fd) > 0) {
		ret = fseek(fd, 1, SEEK_CUR);
		if (ret != 0) {
			fclose(fd);
			throw new Exception(ERR_SEEK);
		}
	}

	c_long begin = ftell(fd);

	/* allocate line size */
	char *buf = cast(char*)calloc(end - begin, char.sizeof);
	if (!buf) {
		fclose(fd);
		throw new Exception(ERR_CALLOC);
	}

	/* read last line */
	char *rets = fgets(buf, cast(int)(end - begin), fd);
	if (!rets) {
		fclose(fd);
		free(buf);
		throw new Exception(ERR_FGETS);
	}

	fclose(fd);

	/* to string */
	string line = buf.fromStringz.idup;
	free(buf);

	/* read the csv */
	ulong id = 0;
	foreach (record; line
			.csvReader!(Tuple!(ulong, string, string))(',')) {
		id = record[0];
	}

	return id;
}

/**
 * Log into GitHub.
 * Params:
 *   askPassword = if we should ask the password or try to use the cached one.
 *   credcache = file that caches the credentials for reuse
 * Returns:
 *   an openend HTTP socket where we logged in.
 */
HTTP getAuthentication(bool askPassword, string credcache)
{
	import std.process : executeShell;


	string username, passwd;

	if (exists(credcache) && !askPassword) {
		File login = File(credcache, "r");
		JSONValue j = parseJSON(login.byLine().joiner("\n"));
		username = j["username"].str;
		passwd = j["passwd"].str;
	} else {
		writeln("Please sign in into your GitHub account.");
		write("login: ");
		username = chomp(readln());

		write("password: ");
		executeShell("stty -echo");
		passwd = chomp(readln());
		executeShell("stty echo");
		write("\n");

		if (!askPassword) {
			File login = File(credcache, "w");
			JSONValue j = ["username": username, "passwd": passwd];
			login.writeln(j.toString());
		}
	}

	auto conn = HTTP();
	conn.setAuthentication(username, passwd);

	return conn;
}

/**
 * Worker that will crawl the user logins and transmit this to the public key workers.
 * Params:
 *   pubkey = array of public key workers
 *   conn = the HTTP socket which we will use to gather user names.
 *   startid = the first id we will crawl
 * Returns:
 *  the status code of this thread.
 *   0 means success
 *  -1 means that we have some bad login infos.
 *  -2 means that we exhausted the call API.
 *  -3 means that we got another type of error.
 */
int userworker(Tid[] pubkey, HTTP conn, ulong startid)
{
	enum API_ADDRESS = "https://api.github.com/users?since=";
	bool loop = true;
	ulong id = startid;
	int retcode = 0;
	size_t workerid = 0;

	while (loop) {
		try {
			auto raw = get(API_ADDRESS ~ to!string(id), conn);

			JSONValue[] array = parseJSON(raw).array();

			if (array.length != 0) {
				foreach (ref a; parallel(array)) {
					send(pubkey[workerid], to!ulong(a["id"].integer), a["login"].str);
					/* round robin of worker */
					workerid = (workerid + 1) % pubkey.length;
				}
				id = array[$ - 1]["id"].integer;
			} else {
				loop = false;
				writeln("[DONE] Finished crawling.");
			}
		} catch (CurlException ce) {
			const int statuscode = conn.statusLine().code;
			if (statuscode == 401) {
				stderr.writeln("[ERROR] Bad credentials.");
				loop = false;
				retcode = -1;
			} else if (statuscode == 403) {
				stderr.writeln("[ERROR] API call exhausted.");
				loop = false;
				retcode = -2;
			} else {
				stderr.writeln("[ERROR] ", ce.msg);
				loop = false;
				retcode = -3;
			}
		}
	}

	writeln("Stopping main user worker.");

	return retcode;
}

/**
 * Worker that will gather public keys given a login name.
 * Params:
 *   parentTid = parent thread id
 *   printworker = print worker thread id
 */
void pubkeyworker(Tid parentTid, Tid printworker, bool crawlGPGKeys)
{
	bool loop = true;
	HTTP conn = HTTP();

	while (loop) {
		receive(
			(ulong id, ref string login) {
				getpubkeys(printworker, conn, id, login, crawlGPGKeys);
			},
			(string fin) {
				if (fin == "FIN") {
					loop = false;
					send(parentTid, "FIN-ACK");
				}
			}
		);
	}
	writeln("Stopping pubkey worker ", thisTid(), ".");
}

/**
 * Gather the public keys of one user.
 * Params:
 *   printworker = print worker thread id
 *   conn = HTTP socket to gather the public keys from.
 *   id = the user id we are crawling
 *   login = the user name we are crawling
 */
void getpubkeys(Tid printworker, HTTP conn, ulong id, ref string login, bool crawlGPGKeys)
{
	enum GITHUB_ADDRESS = "https://github.com/";
	enum GITHUB_GPG_ADDRESS = "https://api.github.com/users/";

	try {
		if (crawlGPGKeys) {
			auto raw = get(GITHUB_GPG_ADDRESS ~ login ~ "/gpg_keys", conn);
			JSONValue[] array = parseJSON(raw).array();
			if (array.length != 0) {
				foreach (ref a; parallel(array)) {
					send(printworker, id, login, a["public_key"].str, a["raw_key"].str);
				}
			}
		} else {
			foreach (line; byLine(GITHUB_ADDRESS ~ login ~ ".keys", KeepTerminator.no, '\n', conn)) {
				/*
				 * Weird users such as 'session' or 'readme' return bad data.
				 * Luckily, the first line of that kind of input is empty,
				 * so we do detect them like that and ignore them.
				 * For this same reason, one should not use parallel since it may hang the whole.
				 */
				if (line.length == 0) {
					writeln("User ", login, ": Redirected page.");
					return;
				}
				send(printworker, id, login, to!string(line));
			}
		}
	} catch (CurlException ce) {
		writeln("User ", login, ": Got a ", conn.statusLine().code, " HTTP return code.");
	}
}

/**
 * Worker that writes the crawl result into a file.
 * Params:
 *   parentTid = parent thread id
 *   filename = output file
 */
void printworker(Tid parentTid, string filename)
{
	File output = File(filename, "a");
	bool loop = true;

	while (loop) {
		receive(
			(ulong id, ref string login, ref string key) {
				output.writefln("%d,\"%s\",\"%s\"", id, login, key);
			},
			(ulong id, ref string login, ref string public_key, ref string raw_key) {
				import std.base64;
				output.writefln("%d,\"%s\",\"%s\",\"%s\"", id, login, public_key, Base64.encode(representation(raw_key)));
			},
			(string fin) {
				if (fin == "FIN") {
					loop = false;
					send(parentTid, "FIN-ACK");
				}
			}
		);
		output.flush();
	}
	writeln("Stopping print worker.");
}
