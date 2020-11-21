-- json = require "cjson.safe"
name = "lua_alert.json"

suffix_list = {"Inc", "and Sons", "LLC", "Group"}

ou_list = {"auxiliary", "primary", "back.end", "digital", "open.source", "virtual", "cross.platform", "redundant", "online", "haptic", "multi.byte", "bluetooth", "wireless", "1080p", "neural", "optical", "solid.state", "mobile", "driver", "protocol", "bandwidth", "panel", "microchip", "program", "port", "card", "array", "interface", "system", "sensor", "firewall", "hard.drive", "pixel", "alarm", "feed", "monitor", "application", "transmitter", "bus", "circuit", "capacitor", "matrix", "back.up", "bypass", "hack", "override", "compress", "copy", "navigate", "index", "connect", "generate", "quantify", "calculate", "synthesize", "input", "transmit", "program", "reboot", "parse"}

last_name_list = {"Abbott", "Abernathy", "Abshire", "Adams", "Altenwerth", "Anderson", "Ankunding", "Armstrong", "Auer", "Aufderhar", "Bahringer", "Bailey", "Balistreri", "Barrows", "Bartell", "Bartoletti", "Barton", "Bashirian", "Batz", "Bauch", "Baumbach", "Bayer", "Beahan", "Beatty", "Bechtelar", "Becker", "Bednar", "Beer", "Beier", "Berge", "Bergnaum", "Bergstrom", "Bernhard", "Bernier", "Bins", "Blanda", "Blick", "Block", "Bode", "Boehm", "Bogan", "Bogisich", "Borer", "Bosco", "Botsford", "Boyer", "Boyle", "Bradtke", "Brakus", "Braun", "Breitenberg", "Brekke", "Brown", "Bruen", "Buckridge", "Carroll", "Carter", "Cartwright", "Casper", "Cassin", "Champlin", "Christiansen", "Cole", "Collier", "Collins", "Conn", "Connelly", "Conroy", "Considine", "Corkery", "Cormier", "Corwin", "Cremin", "Crist", "Crona", "Cronin", "Crooks", "Cruickshank", "Cummerata", "Cummings", "Dach", "D'Amore", "Daniel", "Dare", "Daugherty", "Davis", "Deckow", "Denesik", "Dibbert", "Dickens", "Dicki", "Dickinson", "Dietrich", "Donnelly", "Dooley", "Douglas", "Doyle", "DuBuque", "Durgan", "Ebert", "Effertz", "Emard", "Emmerich", "Erdman", "Ernser", "Fadel", "Fahey", "Farrell", "Fay", "Feeney", "Feest", "Feil", "Ferry", "Fisher", "Flatley", "Frami", "Franecki", "Friesen", "Fritsch", "Funk", "Gaylord", "Gerhold", "Gerlach", "Gibson", "Gislason", "Gleason", "Gleichner", "Glover", "Goldner", "Goodwin", "Gorczany", "Gottlieb", "Goyette", "Grady", "Graham", "Grant", "Green", "Greenfelder", "Greenholt", "Grimes", "Gulgowski", "Gusikowski", "Gutkowski", "Gutmann", "Haag", "Hackett", "Hagenes", "Hahn", "Haley", "Halvorson", "Hamill", "Hammes", "Hand", "Hane", "Hansen", "Harber", "Harris", "Hartmann", "Harvey", "Hauck", "Hayes", "Heaney", "Heathcote", "Hegmann", "Heidenreich", "Heller", "Herman", "Hermann", "Hermiston", "Herzog", "Hessel", "Hettinger", "Hickle", "Hilll", "Hills", "Hilpert", "Hintz", "Hirthe", "Hodkiewicz", "Hoeger", "Homenick", "Hoppe", "Howe", "Howell", "Hudson", "Huel", "Huels", "Hyatt", "Jacobi", "Jacobs", "Jacobson", "Jakubowski", "Jaskolski", "Jast", "Jenkins", "Jerde", "Johns", "Johnson", "Johnston", "Jones", "Kassulke", "Kautzer", "Keebler", "Keeling", "Kemmer", "Kerluke", "Kertzmann", "Kessler", "Kiehn", "Kihn", "Kilback", "King", "Kirlin", "Klein", "Kling", "Klocko", "Koch", "Koelpin", "Koepp", "Kohler", "Konopelski", "Koss", "Kovacek", "Kozey", "Krajcik", "Kreiger", "Kris", "Kshlerin", "Kub", "Kuhic", "Kuhlman", "Kuhn", "Kulas", "Kunde", "Kunze", "Kuphal", "Kutch", "Kuvalis", "Labadie", "Lakin", "Lang", "Langosh", "Langworth", "Larkin", "Larson", "Leannon", "Lebsack", "Ledner", "Leffler", "Legros", "Lehner", "Lemke", "Lesch", "Leuschke", "Lind", "Lindgren", "Littel", "Little", "Lockman", "Lowe", "Lubowitz", "Lueilwitz", "Luettgen", "Lynch", "Macejkovic", "MacGyver", "Maggio", "Mann", "Mante", "Marks", "Marquardt", "Marvin", "Mayer", "Mayert", "McClure", "McCullough", "McDermott", "McGlynn", "McKenzie", "McLaughlin", "Medhurst", "Mertz", "Metz", "Miller", "Mills", "Mitchell", "Moen", "Mohr", "Monahan", "Moore", "Morar", "Morissette", "Mosciski", "Mraz", "Mueller", "Muller", "Murazik", "Murphy", "Murray", "Nader", "Nicolas", "Nienow", "Nikolaus", "Nitzsche", "Nolan", "Oberbrunner", "O'Connell", "O'Conner", "O'Hara", "O'Keefe", "O'Kon", "Okuneva", "Olson", "Ondricka", "O'Reilly", "Orn", "Ortiz", "Osinski", "Pacocha", "Padberg", "Pagac", "Parisian", "Parker", "Paucek", "Pfannerstill", "Pfeffer", "Pollich", "Pouros", "Powlowski", "Predovic", "Price", "Prohaska", "Prosacco", "Purdy", "Quigley", "Quitzon", "Rath", "Ratke", "Rau", "Raynor", "Reichel", "Reichert", "Reilly", "Reinger", "Rempel", "Renner", "Reynolds", "Rice", "Rippin", "Ritchie", "Robel", "Roberts", "Rodriguez", "Rogahn", "Rohan", "Rolfson", "Romaguera", "Roob", "Rosenbaum", "Rowe", "Ruecker", "Runolfsdottir", "Runolfsson", "Runte", "Russel", "Rutherford", "Ryan", "Sanford", "Satterfield", "Sauer", "Sawayn", "Schaden", "Schaefer", "Schamberger", "Schiller", "Schimmel", "Schinner", "Schmeler", "Schmidt", "Schmitt", "Schneider", "Schoen", "Schowalter", "Schroeder", "Schulist", "Schultz", "Schumm", "Schuppe", "Schuster", "Senger", "Shanahan", "Shields", "Simonis", "Sipes", "Skiles", "Smith", "Smitham", "Spencer", "Spinka", "Sporer", "Stamm", "Stanton", "Stark", "Stehr", "Steuber", "Stiedemann", "Stokes", "Stoltenberg", "Stracke", "Streich", "Stroman", "Strosin", "Swaniawski", "Swift", "Terry", "Thiel", "Thompson", "Tillman", "Torp", "Torphy", "Towne", "Toy", "Trantow", "Tremblay", "Treutel", "Tromp", "Turcotte", "Turner", "Ullrich", "Upton", "Vandervort", "Veum", "Volkman", "Von", "VonRueden", "Waelchi", "Walker", "Walsh", "Walter", "Ward", "Waters", "Watsica", "Weber", "Wehner", "Weimann", "Weissnat", "Welch", "West", "White", "Wiegand", "Wilderman", "Wilkinson", "Will", "Williamson", "Willms", "Windler", "Wintheiser", "Wisoky", "Wisozk", "Witting", "Wiza", "Wolf", "Wolff", "Wuckert", "Wunsch", "Wyman", "Yost", "Yundt", "Zboncak", "Zemlak", "Ziemann", "Zieme", "Zulauf"}


state_abbr_list = {"AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"}


function string.trim(s)
    return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end

function  in_array(b,list)
    if not list then
        return false   
    end 
    if list then
        for k, v in ipairs(list) do
            if v == b then
                return true
            end
        end
    end
end 


function init (args)
    local needs = {}
    needs["protocol"] = "tls"
    return needs
end

function setup (args)
    filename = SCLogPath() .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("Tls log Filename " .. filename)
end

function log (args)
    version, subject, issuer, fingerprint = TlsGetCertInfo()

    if subject ~= nil then
	    if string.match(string.trim(subject),"C=(%w+),%sST=(%w+),%sO=(.*),%sOU=(.*),%sCN=") ~= nil then
	        C,ST,O,OU = string.match(string.trim(subject),"C=(%w+),%sST=(%w+),%sO=(.*),%sOU=(.*),%sCN=")
			if C == "US" then
				-- SCLogInfo("detection tls_c")
				-- SCLogInfo(ST)
				if in_array(ST, state_abbr_list) then
					-- SCLogInfo("detection tls_st")
					if in_array(OU, ou_list) then
						-- SCLogInfo("detection tls_ou\n")
						if string.match(string.trim(O),"(%w+)%s+(%w+)") ~= 'nil' then
							last_name, suffix = string.match(string.trim(O),"(%w+)%s+(%w+)")
							if in_array(suffix, suffix_list) then
								if in_array(last_name, last_name_list) then
										-- SCLogInfo("detection tls_o")
									ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()
										-- alarm_data = {
										--	msg = 'MSF certs detection',
										--	src_ip = src_ip,
										--	dest_ip = dest_ip,
										--	src_port = src_port,
										--	dst_port = dst_port,
										--	protocol = protocol
										--}
										--data = json.encode(alarm_data)
										--file:write(data .. "\n")
									file:write("{msg:\"MSF certs detection\", src_ip:\"" .. src_ip .. ",\" dest_ip:\"" .. dst_ip .. "\", src_port:\"" .. src_port .. "\", dest_port:\"" .. dst_port .. "\", protocol:\"" .. protocol .. "\"}")
									file:flush()

								end
							end
						end

						if string.match(string.trim(O),"(%w+)-(%w+)") ~= 'nil' then
							last_name1, last_name2 = string.match(string.trim(O),"(%w+)-(%w+)")
							if in_array(last_name1, last_name_list) then
								if in_array(last_name2, last_name_list) then
									-- SCLogInfo("detection tls_o")
									ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()
									-- alarm_data = {
									-- 	msg = 'MSF certs detection',
									-- 	src_ip = src_ip,
									-- 	dest_ip = dest_ip,
									-- 	src_port = src_port,
									-- 	dst_port = dst_port,
									--	protocol = protocol
									-- }
									-- data = json.encode(alarm_data)
									-- file:write(data .. "\n")
									file:write("{msg:\"MSF certs detection\", src_ip:\"" .. src_ip .. ",\" dest_ip:\"" .. dst_ip .. "\", src_port:\"" .. src_port .. "\", dest_port:\"" .. dst_port .. "\", protocol:\"" .. protocol .. "\"}")
									file:flush()
								end
							end
						end
						if string.match(string.trim(O),"(%w+),%s+(%w+)%s+and%s+(%w+)") ~= 'nil' then
							last_name1, last_name2, last_name3 = string.match(string.trim(O),"(%w+),%s+(%w+)%s+and%s+(%w+)")
							if in_array(last_name1, last_name_list) then
								if in_array(last_name2, last_name_list) then
									if in_array(last_name3, last_name_list) then
										-- SCLogInfo("detection tls_o")
										ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()
										-- alarm_data = {
										-- 	msg = 'MSF certs detection',
										-- 	src_ip = src_ip,
										-- 	dest_ip = dest_ip,
										-- 	src_port = src_port,
										-- 	dst_port = dst_port,
										-- 	protocol = protocol
										-- }
										-- data = json.encode(alarm_data)
										-- file:write(data .. "\n")
										file:write("{msg:\"MSF certs detection\", src_ip:\"" .. src_ip .. ",\" dest_ip:\"" .. dst_ip .. "\", src_port:\"" .. src_port .. "\", dest_port:\"" .. dst_port .. "\", protocol:\"" .. protocol .. "\"}")
										file:flush()
									end
								end
							end
						end
					end 
				end
			end
		end
	end
end


function deinit (args)
	SCLogInfo ("Tls transactions logged: ");
    file:close(file)
end
