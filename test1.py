def parseInput(inputTuple):
	input_data = inputTuple.split()
	source_ip = input_data[0]
	source_port = input_data[1]
	dest_ip = input_data[2]
	dest_port = input_data[3]
	proto = input_data[4]
	#print "Source IP: ",source_ip, "Protocol: ", proto
	return (source_ip,proto)

def parseRule(rule,sip,proto):
	rule_data = rule.split()
	if rule_data[1] == sip:
		#print "SourceIP matched"
		if rule_data[3] == proto:
			#print "Protocol matched"
			return rule_data[4]
		else:
			return "Not Matched"
	else:
		return "Not Matched"
		


print ("This is the Demo for firewall\n")
i = open('input.txt','r')
#print i



for line in i:
	#print "calling pareser"
	sip_input, proto_input = parseInput(line)
	#print sip
	#print sport 
	j = open('rules.txt', 'r')
	for rule in j:
		#print "Inside Rules"
		result = parseRule(rule,sip_input,proto_input)
		#print result
		if (result == "ACCEPT" or result == "DROP"):
			print (result)
			break;
		else:
			result = "DROP"

	outfile = open('output.txt','a')
	entry = sip_input +" " +result + '\n'
	outfile.write(entry)
	outfile.close()
