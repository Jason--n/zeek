##! This script logs information about packet protocols that Zeek doesn't
##! know how to process. Mostly these come from packet analysis plugins when
##! they attempt to forward to the next analyzer, but they also can originate
##! from non-packet analyzers.

@load base/frameworks/notice

module UnknownProtocol;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Timestamp for when the measurement occurred.
		ts:           time     &log;
		##
		analyzer:     string   &log;
		protocol:     string   &log;
		first_bytes:  string   &log;
	};

	## How many reports for an analyzer/protocol pair will be allowed to
	## raise events for logging being rate-limited.
	option sampling_threshold : count = 25 &redef;

	## The rate-limiting sampling rate. One out of every of this number of
	## rate-limited pairs of a given type will be allowed to raise events
	## for further script-layer handling. Setting the sampling rate to 0
	## will disable all output of rate-limited pairs.
	option sampling_rate : count = 1000 &redef;

	## How long an analyzer/protocol pair is allowed to keep state/counters in
	## in memory. Once the threshold has been hit, this is the amount of time
	## before the rate-limiting for a pair expires and is reset.
	option sampling_duration = 10min &redef;

	## The number of bytes to extract from the next header and log in the
	## first bytes field.
	option first_bytes_count = 10 &redef;
}

event unknown_protocol(analyzer_name: string, protocol: count, first_bytes: string)
	{
	local info : Info;
	info$ts = network_time();
	info$analyzer = analyzer_name;
	info$protocol = fmt("0x%x", protocol);
	info$first_bytes = first_bytes;

	Log::write(LOG, info);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $path="unknown_protocols", $policy=log_policy]);
	}
