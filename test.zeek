global agentTable :table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string) {
	if (c$http?$user_agent){
		local orig_addr = c$id$orig_h;
		local user_agent = to_lower(c$http$user_agent);
		if (orig_addr in agentTable) {
			add (agentTable[orig_addr])[user_agent];
		} else {
			agentTable[orig_addr] = set(user_agent);
		}
	}
}

event zeek_done() {
	for (orig_addr in agentTable) {
		if (|agentTable[orig_addr]| >= 3) {
			print fmt("%s is a proxy", orig_addr);
		}
	}
}
