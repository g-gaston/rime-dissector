print("loading NullRDC rime-ibc dissector")

rime_proto = Proto("rime","Contiki Rime")

-- dissect
function rime_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "RIME"

	local mac_tree = tree:add(rime_proto, buffer(0, 9), "IEEE 802.15.4")
	local fcf_tree = mac_tree:add(rime_proto, buffer(0, 2), "Frame Control Field 0x" .. tostring(buffer(1, 1))..tostring(buffer(0,1)))
	local f_type = buffer(0,1):bitfield(5,3)
	local security = ""
	local frame_pen = ""
	local ack = ""
	local intra_pan = ""
	local dst_add = buffer(1,1):bitfield(4,2)
	local src_add = buffer(1,1):bitfield(0,2)

	if f_type == 1 then
		f_type = "Data"
	elseif f_type == 0 then
		f_type = "Beacon"
	elseif f_type == 2 then
		f_type = "ACK"
	elseif f_type == 3 then
		f_type = "Comando"
	else
		f_type = "Reserved"
	end

	if buffer(0,1):bitfield(4,1) == 1 then
		security = "True"
	else
		security = "False"
	end

	if buffer(0,1):bitfield(3,1) == 1 then
		frame_pen = "True"
	else
		frame_pen = "False"
	end

	if buffer(0,1):bitfield(2,1) == 1 then
		ack = "True"
	else
		ack = "False"
	end

	if buffer(0,1):bitfield(1,1) == 1 then
		intra_pan = "True"
	else
		intra_pan = "False"
	end

	if dst_add == 2 then
		dst_add = "Short/16-bit"
	elseif dst_add == 0 then
		dst_add = "Address and PAN ID no present"
	elseif dst_add == 3 then
		dst_add = "Long/64-bit"
	else
		dst_add = "Reserved"
	end

	if src_add == 2 then
		src_add = "Short/16-bit"
	elseif src_add == 0 then
		src_add = "Address and PAN ID no present"
	elseif src_add == 3 then
		src_add = "Long/64-bit"
	else
		src_add = "Reserved"
	end

	fcf_tree:add(buffer(0,1), "Frame Type: ", f_type)
	fcf_tree:add(buffer(0,1), "Security Enabled: ", security)
	fcf_tree:add(buffer(0,1), "Frame Pending: ", frame_pen)
	fcf_tree:add(buffer(0,1), "Acknowledge Request: ", ack)
	fcf_tree:add(buffer(0,1), "Intra-PAN: ", intra_pan)

	fcf_tree:add(buffer(1,1), "Destination Addressing Mode: ", dst_add)
	fcf_tree:add(buffer(1,1), "Frame Version: ", buffer(1,1):bitfield(2,2))
	fcf_tree:add(buffer(1,1), "Source Addressing Mode: ", src_add)

	mac_tree:add(buffer(2,1), "Sequence Number: " .. buffer(2,1):uint())
	mac_tree:add(buffer(3,2),"Destination PAN: 0x" .. tostring(buffer(4,1))..tostring(buffer(3,1)))
	mac_tree:add(buffer(5,2),"Destination: 0x" .. tostring(buffer(6,1))..tostring(buffer(5,1)))
	mac_tree:add(buffer(7,2),"Source: 0x" .. tostring(buffer(8,1))..tostring(buffer(7,1)))
	mac_tree:add(buffer(buffer:len()-2, 2), "CRC: ", buffer(buffer:len()-2, 2):uint())

	local rime_tree = tree:add(rime_proto, buffer(9, 4), "RIME")
	rime_tree:add(buffer(9,2), "Channel: " .. buffer(9,2):le_uint())
	rime_tree:add(buffer(11,2),"Source Address: " .. buffer(11,1):uint() .. ":" .. buffer(12,1):uint())

	local data_tree = tree:add(rime_proto, buffer(13, buffer:len() - 15), "Payload")

	pinfo.cols.info = "Rime ibc on channel " .. buffer(9,2):le_uint()
	pinfo.cols.src = "" .. buffer(11,1):uint() .. ":" .. buffer(12,1):uint()
	pinfo.cols.dst = "Broadcast"
end

-- get wiretap table
table = DissectorTable.get("wtap_encap")
-- and add rime protocol
table:add(wtap["IEEE802_15_4"], rime_proto)


