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

function module.Update(name: string, typeo: number, details: string, state: string, assets: {}, appid:number)
	assert(connection, "cant update if not started")
	if assets then
		module.assets = assets
	end
	if appid then
		module.appid = appid
	end
	connection:Send(HttpService:JSONEncode({
		op = 3,
		d = {
			since = 0,
			activities = {{
				name = name or "no name",
				type = typeo or 0,
				details = details or "No Details!",
				state = state or "No state!",
				application_id = module.appid,
				assets = module.assets,
				timestamps = { start = module.starttime }
			}},
			status = "online",
			afk = false
		}
	}))
end

function module.Init(Token: string, name: string, typeo: number, details: string, state: string, assets: {}, appid:number)
	assert(Token ~= "", "token must be provided")
	
	connection = ws.connect("wss://gateway.discord.gg/?v=10&encoding=json")
	
	if assets then
		module.assets = assets
	end
	if appid then
		module.appid = appid
	end
	
	connection.OnMessage:Connect(function(message)
		local data = HttpService:JSONDecode(message)

		if data.op == 10 then
			local interval = data.d.heartbeat_interval
			Heartbeat(interval)

			module.starttime = os.time() * 1000

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
							application_id = module.appid or 0,
							state = state or "No state!",
							assets = module.assets or {},
							timestamps = { start = module.starttime }
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
