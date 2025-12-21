local module = {}

local ws = Websocket or WebSocket
local HttpService = game:GetService("HttpService")

local function Heartbeat(interval)
	task.spawn(function()
		while task.wait(interval / 1000) and connection do
			connection:Send(HttpService:JSONEncode({
				op = 1,
				d = ""
			}))
		end
	end)
end

function module.Update(name: string, typeo: number, details: string, state: string, assets: {})
	assert(connection, "cant update if not started")
	connection:Send(HttpService:JSONEncode({
		op = 3,
		d = {
			since = 0,
			activities = {{
				name = name or "no name",
				type = typeo or 0,
				details = details or "No Details!",
				state = state or "No state!",
				assets = assets or module.assets,
				timestamps = { start = os.time() * 1000 }
			}},
			status = "online",
			afk = false
		}
	}))
end

function module.Init(Token: string, name: string, typeo: number, details: string, state: string, assets: {})
	assert(Token ~= "", "token must be provided")
	
	connection = ws.connect("wss://gateway.discord.gg/?v=10&encoding=json")
	
	if assets then
		module.assets = assets
	end
	
	connection.OnMessage:Connect(function(message)
		local data = HttpService:JSONDecode(message)

		if data.op == 10 then
			local interval = data.d.heartbeat_interval
			Heartbeat(interval)

			connection:Send(HttpService:JSONEncode({
				op = 2,
				d = {
					token = Token,
					properties = {
						["$os"] = "windows",
						["$browser"] = "NullFire",
						["$device"] = "NF"
					},
					presence = {
						activities = {{
							name = name or "no name",
							type = typeo or 0,
							details = details or "No Details!",
							state = state or "No state!",
							assets = module.assets or {},
							timestamps = { start = os.time() * 1000 }
						}},
						status = "online",
						afk = false
					}
				}
			}))
		end
	end)
	
	module.connected = true
end

function module.Stop()
	assert(connection, "cant stop if not even started!")
	connection:Close()
	connection = nil
	module.connected = false
end

return module
