--[[

  Crypt Library v0.5
  
  Exported hash functions:
    crypt.md2			MD2
    crypt.md4			MD4
    crypt.md5			MD5
    crypt.crc32		CRC32 (IEEE 802.3)
    crypt.sha1			SHA-1
    crypt.sha224		SHA-224
    crypt.sha256		SHA-256
    crypt.sha384		SHA-384
    crypt.sha512		SHA-512
    crypt.ripemd128	RIPEMD-128
crypt.derive		derive

  Sample hash function usage:
    > print(_G.crypt.md2("abc"))
    da853b0d3f88d99b30283a69e6ded6bb

  Please send a PM to http://www.roblox.com/My/PrivateMessage.aspx?RecipientID=19057889
      if you discover any bugs or errors.
]]

local ins=table.insert
local mf=math.floor
local bnot=function(i)
	return 4294967295-i
end

local bnot16=function(i)
	return 65535-i
end

local bnot64=function(a,b)
	return bnot(a),bnot(b)
end

local band=function(a,b)
	local t=0
	local e,f=mf(a),mf(b)
	for n=0,7 do
		local j,k=e%2,f%2
		t=t*.5+(((j==1)and(k==1))and 1 or 0)
		e=(e-j)*.5
		f=(f-k)*.5
	end
	return t*2^7
end

local andlut = {}
for x = 0, 255 do
	andlut[x] = {}
	for y = 0, 255 do
		andlut[x][y] = band(x, y)
	end
end

local function band(a,b)
	a = a * (1/256)
	b = b * (1/256)
	local _a, _b = a%1, b%1
	local c = andlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	a = a * (1/256)
	b = b * (1/256)
	_a, _b = a%1, b%1
	c = c * (1/256) + andlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	a = a * (1/256)
	b = b * (1/256)
	_a, _b = a%1, b%1
	c = c * (1/256) + andlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	return (c * (1/256) + andlut[a][b]) * 2^24
end

local band16=function(a,b)
	local _a, _b = a % 256, b % 256
	a, b = (a - _a) * (1/256), (b - _b) * (1/256)
	return andlut[a][b] * 256 + andlut[_a][_b]
end

local band8=function(a,b)
	return andlut[a][b]
end

local band64=function(a,b,c,d)
	return band(a,c),band(b,d)
end

local bor=function(a,b)
	local t=0
	local e,f=mf(a),mf(b)
	for n=0,7 do
		local j,k=e%2,f%2
		t=t*.5+(((j==1)or(k==1))and 1 or 0)
		e=(e-j)*.5
		f=(f-k)*.5
	end
	return t*2^7
end

local orlut = {}
for x = 0, 255 do
	orlut[x] = {}
	for y = 0, 255 do
		orlut[x][y] = bor(x, y)
	end
end

local function bor(a,b)
	--print(a,b)
	a = a * (1/256)
	b = b * (1/256)
	local _a, _b = a%1, b%1
	local c = orlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	a = a * (1/256)
	b = b * (1/256)
	_a, _b = a%1, b%1
	c = c * (1/256) + orlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	a = a * (1/256)
	b = b * (1/256)
	_a, _b = a%1, b%1
	c = c * (1/256) + orlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	return (c * (1/256) + orlut[a][b]) * 2^24
end

local bor16=function(a,b)
	local _a, _b = a % 256, b % 256
	a, b = (a - _a) * (1/256), (b - _b) * (1/256)
	return orlut[a][b] * 256 + orlut[_a][_b]
end

local bor8=function(a,b)
	return orlut[a][b]
end

local bor64=function(a,b,c,d)
	return bor(a,c),bor(b,d)
end

local bxor=function(a,b)
	local t=0
	local e,f=mf(a),mf(b)
	for n=0,7 do
		local j,k=e%2,f%2
		t=t*.5+(((j~=k))and 1 or 0)
		e=(e-j)*.5
		f=(f-k)*.5
	end
	return t*2^7
end

local xorlut = {}
for x = 0, 255 do
	xorlut[x] = {}
	for y = 0, 255 do
		xorlut[x][y] = bxor(x, y)
	end
end

local function bxor(a,b)
	a = a * (1/256)
	b = b * (1/256)
	local _a, _b = a%1, b%1
	local c = xorlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	a = a * (1/256)
	b = b * (1/256)
	_a, _b = a%1, b%1
	c = c * (1/256) + xorlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	a = a * (1/256)
	b = b * (1/256)
	_a, _b = a%1, b%1
	c = c * (1/256) + xorlut[_a*256][_b*256]
	a, b = a - _a, b - _b
	return (c * (1/256) + xorlut[a][b]) * 2^24
end

local bxor16=function(a,b)
	local _a, _b = a % 256, b % 256
	a, b = (a - _a) * (1/256), (b - _b) * (1/256)
	return xorlut[a][b] * 256 + xorlut[_a][_b]
end

local bxor8=function(a,b)
	return xorlut[a][b]
end

local bxor64=function(a,b,c,d)
	return bxor(a,c),bxor(b,d)
end

local lshift=function(n,s)
	return mf(n*2^s)%2^32
end

local rshift=function(n,s)
	return mf(n*.5^s)%2^32
end

local lshift64=function(x,y,s)
	local b=lshift(y,s)
	local a=bor(lshift(x,s),rshift(y,32-s))
	return a,b
end

local rshift64=function(x,y,s)
	local a=rshift(x,s)
	local b=bor(rshift(y,s),lshift(x,32-s))
	return a,b
end

local lrotate=function (n,s)
	return bor(lshift(n,s),rshift(n,32-s))
end

local lrotate16=function (n,s)
	return bor16(lshift(n,s),rshift(n,16-s))
end

local rrotate=function (n,s)
	return bor(rshift(n,s),lshift(n,32-s))
end

local rrotate16=function (n,s)
	return bor16(rshift(n,s),lshift(n,16-s))
end

local rrotate64=function (x,y,s)
	local a,b = rshift64(x,y,s)
	local c,d = lshift64(x,y,64-s)
	return bor64(a,b,c,d)
end

local chr = string.char

local leIstr=function(i)
	local _1 = i % 256
	i = (i - _1) * (1 / 256)
	local _2 = i % 256
	i = (i - _2) * (1 / 256)
	local _3 = i % 256
	i = (i - _3) * (1 / 256)
	return chr(_1)..chr(_2)..chr(_3)..chr(i%256)
end

local beIstr=function(i)
	local _1 = i % 256
	i = (i - _1) * (1 / 256)
	local _2 = i % 256
	i = (i - _2) * (1 / 256)
	local _3 = i % 256
	i = (i - _3) * (1 / 256)
	return chr(i%256)..chr(_3)..chr(_2)..chr(_1)
end

local beInt=function(s)
	local v=0
	for i=1,#s do v=v*256+s:byte(i)end
	return v
end
local leInt=function(s)
	local v=0
	for i=#s,1,-1 do v=v*256+s:byte(i) end
	return v
end
local beStrCuts=function(s)
	local o,r=1,{}
	for i=1,16 do
		ins(r,beInt(s:sub(o,o+3)))
		o=o+4
	end
	return r
end
local leStrCuts=function(s)
	local o,r=1,{}
	for i=1,16 do
		ins(r,leInt(s:sub(o,o+3)))
		o=o+4
	end
	return r
end


local crypt={}
_G.crypt=crypt
local f=function (x,y,z) return bor(band(x,y),band(bnot(x),z)) end
local g=function (x,y,z) return bor(band(x,z),band(y,bnot(z))) end
local h=function (x,y,z) return bxor(x,bxor(y,z)) end
local i=function (x,y,z) return bxor(y,bor(x,bnot(z))) end
local z=function (f,a,b,c,d,x,s,ac)
	local a=(a+f(b,c,d)+x+ac)%2^32
	-- be *very* careful that left shift does not cause rounding!
	return (lshift(band(a,rshift(2^32-1,s)),s)+rshift(a,32-s)+b)%2^32
end
local z2=function (f,a,b,c,d,x,s,ac)
	local a=(a+f(b,c,d)+x+ac)%2^32 --    
	-- be *very* careful that left shift does not cause rounding!
	return lshift(a,s)+rshift(a,32-s) --,2^32-1) band(
end
local swap=function (w) return beInt(leIstr(w)) end

function crypt.md5(s)
	local msgLen=#s
	local padLen=56-msgLen%64
	if msgLen%64>56 then padLen=padLen+64 end
	if padLen==0 then padLen=64 end
	s=s.."\128"..("\0"):rep(padLen-1)
	s=s..leIstr(8*msgLen)..leIstr(0)
	assert(#s%64==0)
	local a,b,c,d=0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476
	local A,B,C,D
	local z=z
	for _=1,#s,64 do
		local X=leStrCuts(s:sub(_,_+63))

		A,B,C,D=a,b,c,d

		a=z(f,a,b,c,d,X[ 1], 7,0xd76aa478)
		d=z(f,d,a,b,c,X[ 2],12,0xe8c7b756)
		c=z(f,c,d,a,b,X[ 3],17,0x242070db)
		b=z(f,b,c,d,a,X[ 4],22,0xc1bdceee)
		a=z(f,a,b,c,d,X[ 5], 7,0xf57c0faf)
		d=z(f,d,a,b,c,X[ 6],12,0x4787c62a)
		c=z(f,c,d,a,b,X[ 7],17,0xa8304613)
		b=z(f,b,c,d,a,X[ 8],22,0xfd469501)
		a=z(f,a,b,c,d,X[ 9], 7,0x698098d8)
		d=z(f,d,a,b,c,X[10],12,0x8b44f7af)
		c=z(f,c,d,a,b,X[11],17,0xffff5bb1)
		b=z(f,b,c,d,a,X[12],22,0x895cd7be)
		a=z(f,a,b,c,d,X[13], 7,0x6b901122)
		d=z(f,d,a,b,c,X[14],12,0xfd987193)
		c=z(f,c,d,a,b,X[15],17,0xa679438e)
		b=z(f,b,c,d,a,X[16],22,0x49b40821)

		a=z(g,a,b,c,d,X[ 2], 5,0xf61e2562)
		d=z(g,d,a,b,c,X[ 7], 9,0xc040b340)
		c=z(g,c,d,a,b,X[12],14,0x265e5a51)
		b=z(g,b,c,d,a,X[ 1],20,0xe9b6c7aa)
		a=z(g,a,b,c,d,X[ 6], 5,0xd62f105d)
		d=z(g,d,a,b,c,X[11], 9,0x02441453)
		c=z(g,c,d,a,b,X[16],14,0xd8a1e681)
		b=z(g,b,c,d,a,X[ 5],20,0xe7d3fbc8)
		a=z(g,a,b,c,d,X[10], 5,0x21e1cde6)
		d=z(g,d,a,b,c,X[15], 9,0xc33707d6)
		c=z(g,c,d,a,b,X[ 4],14,0xf4d50d87)
		b=z(g,b,c,d,a,X[ 9],20,0x455a14ed)
		a=z(g,a,b,c,d,X[14], 5,0xa9e3e905)
		d=z(g,d,a,b,c,X[ 3], 9,0xfcefa3f8)
		c=z(g,c,d,a,b,X[ 8],14,0x676f02d9)
		b=z(g,b,c,d,a,X[13],20,0x8d2a4c8a)

		a=z(h,a,b,c,d,X[ 6], 4,0xfffa3942)
		d=z(h,d,a,b,c,X[ 9],11,0x8771f681)
		c=z(h,c,d,a,b,X[12],16,0x6d9d6122)
		b=z(h,b,c,d,a,X[15],23,0xfde5380c)
		a=z(h,a,b,c,d,X[ 2], 4,0xa4beea44)
		d=z(h,d,a,b,c,X[ 5],11,0x4bdecfa9)
		c=z(h,c,d,a,b,X[ 8],16,0xf6bb4b60)
		b=z(h,b,c,d,a,X[11],23,0xbebfbc70)
		a=z(h,a,b,c,d,X[14], 4,0x289b7ec6)
		d=z(h,d,a,b,c,X[ 1],11,0xeaa127fa)
		c=z(h,c,d,a,b,X[ 4],16,0xd4ef3085)
		b=z(h,b,c,d,a,X[ 7],23,0x04881d05)
		a=z(h,a,b,c,d,X[10], 4,0xd9d4d039)
		d=z(h,d,a,b,c,X[13],11,0xe6db99e5)
		c=z(h,c,d,a,b,X[16],16,0x1fa27cf8)
		b=z(h,b,c,d,a,X[ 3],23,0xc4ac5665)

		a=z(i,a,b,c,d,X[ 1], 6,0xf4292244)
		d=z(i,d,a,b,c,X[ 8],10,0x432aff97)
		c=z(i,c,d,a,b,X[15],15,0xab9423a7)
		b=z(i,b,c,d,a,X[ 6],21,0xfc93a039)
		a=z(i,a,b,c,d,X[13], 6,0x655b59c3)
		d=z(i,d,a,b,c,X[ 4],10,0x8f0ccc92)
		c=z(i,c,d,a,b,X[11],15,0xffeff47d)
		b=z(i,b,c,d,a,X[ 2],21,0x85845dd1)
		a=z(i,a,b,c,d,X[ 9], 6,0x6fa87e4f)
		d=z(i,d,a,b,c,X[16],10,0xfe2ce6e0)
		c=z(i,c,d,a,b,X[ 7],15,0xa3014314)
		b=z(i,b,c,d,a,X[14],21,0x4e0811a1)
		a=z(i,a,b,c,d,X[ 5], 6,0xf7537e82)
		d=z(i,d,a,b,c,X[12],10,0xbd3af235)
		c=z(i,c,d,a,b,X[ 3],15,0x2ad7d2bb)
		b=z(i,b,c,d,a,X[10],21,0xeb86d391)

		a,b,c,d=(A+a)%2^32,(B+b)%2^32,(C+c)%2^32,(D+d)%2^32

	end
	return ("%08x%08x%08x%08x"):format(swap(a),swap(b),swap(c),swap(d))
end


local poly=0xEDB88320

function crypt.crc32(s)
	local crc=2^32-1
	for _ in s:gmatch"."do
		local t=bxor(crc%256,_:byte())
		for i=1,8 do
			if t%2==1 then
				t=bxor(rshift(t,1),poly)
			else
				t=rshift(t,1)
			end
		end
		crc=bxor(rshift(crc,8),t)
	end
	crc=bnot(crc)
	return string.format("%08x",crc)
end

function crypt.sha1(s)
	local msgLen=#s
	local padLen=56-msgLen%64
	if msgLen%64>56 then padLen=padLen+64 end
	if padLen==0 then padLen=64 end
	s=s.."\128"..("\0"):rep(padLen-1)
	s=s..beIstr(0)..beIstr(8*msgLen)
	assert(#s%64==0)
	local h1,h2,h3,h4,h5=0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0
	for _=1,#s,64 do
		local w=beStrCuts(s:sub(_,_+63))
		for i=17,80 do
			w[i]=lrotate(bxor(bxor(bxor(w[i-3],w[i-8]),w[i-14]),w[i-16]),1)
		end
		local a,b,c,d,e=h1,h2,h3,h4,h5
		for i=1,80 do
			local f,k
			if i<21 then
				f=bor(band(b,c),band(bnot(b),d))
				k=0x5A827999
			elseif i<41 then
				f=bxor(bxor(b,c),d)
				k=0x6ED9EBA1
			elseif i<61 then
				f=bor(bor(band(b,c),band(b,d)),band(c,d))
				k=0x8F1BBCDC
			else
				f=bxor(bxor(b,c),d)
				k=0xCA62C1D6
			end
			f=lrotate(a,5)+f+e+k+w[i]
			e=d
			d=c
			c=lrotate(b,30)
			b=a
			a=f%2^32
		end
		h1=(h1+a)%2^32
		h2=(h2+b)%2^32
		h3=(h3)%2^32
		h4=(h4)%2^32
		h5=(h5)%2^32
	end
	return ("%08x%08x%08x%08x%08x"):format(h1,h2,h3,h4,h5)
end

local k={0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}
function crypt.sha256(s)
	local msgLen=#s
	local padLen=56-msgLen%64
	if msgLen%64>56 then padLen=padLen+64 end
	if padLen==0 then padLen=64 end
	s=s.."\128"..("\0"):rep(padLen-1)
	s=s..beIstr(0)..beIstr(8*msgLen)
	assert(#s%64==0)
	local h1,h2,h3,h4,h5,h6,h7,h8=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
	for _=1,#s,64 do
		local w=beStrCuts(s:sub(_,_+63))
		for i=17,64 do
			local _1,_2 = w[i-15],w[i-2]
			local s0=bxor(bxor(rrotate(_1,7),rrotate(_1,18)),rshift(_1,3))
			local s1=bxor(bxor(rrotate(_2,17),rrotate(_2,19)),rshift(_2,10))
			w[i]=(w[i-16]+s0+w[i-7]+s1)%2^32
		end
		local a,b,c,d,e,f,g,h=h1,h2,h3,h4,h5,h6,h7,h8
		for i=1,64 do
			local s0=bxor(bxor(rrotate(a,2),rrotate(a,13)),rrotate(a,22))
			local s1=bxor(bxor(rrotate(e,6),rrotate(e,11)),rrotate(e,25))
			local t1=h+s1+bxor(band(e,f),band(bnot(e),g))+k[i]+w[i]
			local t2=s0+bxor(bxor(band(a,b),band(a,c)),band(b,c))
			h=g
			g=f
			f=e
			e=(d+t1)%2^32
			d=c
			c=b
			b=a
			a=(t1+t2)%2^32
		end
		h1=(h1+a)%2^32
		h2=(h2+b)%2^32
		h3=(h3+c)%2^32
		h4=(h4+d)%2^32
		h5=(h5+e)%2^32
		h6=(h6+f)%2^32
		h7=(h7+g)%2^32
		h8=(h8+h)%2^32
	end
	return ("%08x%08x%08x%08x%08x%08x%08x%08x"):format(h1,h2,h3,h4,h5,h6,h7,h8)
end

function crypt.sha224(s)
	local msgLen=#s
	local padLen=56-msgLen%64
	if msgLen%64>56 then padLen=padLen+64 end
	if padLen==0 then padLen=64 end
	s=s.."\128"..("\0"):rep(padLen-1)
	s=s..beIstr(0)..beIstr(8*msgLen)
	assert(#s%64==0)
	local h1,h2,h3,h4,h5,h6,h7,h8=0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4

	for _=1,#s,64 do
		local w=beStrCuts(s:sub(_,_+63))
		for i=17,64 do
			local s0=bxor(bxor(rrotate(w[i-15],7),rrotate(w[i-15],18)),rshift(w[i-15],3))
			local s1=bxor(bxor(rrotate(w[i-2],17),rrotate(w[i-2],19)),rshift(w[i-2],10))
			w[i]=(w[i-16]+s0+w[i-7]+s1)%2^32
		end
		local a,b,c,d,e,f,g,h=h1,h2,h3,h4,h5,h6,h7,h8
		for i=1,64 do
			local s0=bxor(bxor(rrotate(a,2),rrotate(a,13)),rrotate(a,22))
			local s1=bxor(bxor(rrotate(e,6),rrotate(e,11)),rrotate(e,25))
			local t1=h+s1+bxor(band(e,f),band(bnot(e),g))+k[i]+w[i]
			local t2=s0+bxor(bxor(band(a,b),band(a,c)),band(b,c))
			h=g
			g=f
			f=e
			e=(d+t1)%2^32
			d=c
			c=b
			b=a
			a=(t1+t2)%2^32
		end
		h1=(h1+a)%2^32
		h2=(h2+b)%2^32
		h3=(h3+c)%2^32
		h4=(h4+d)%2^32
		h5=(h5+e)%2^32
		h6=(h6+f)%2^32
		h7=(h7+g)%2^32
		h8=(h8+h)%2^32
	end
	return ("%08x%08x%08x%08x%08x%08x%08x"):format(h1,h2,h3,h4,h5,h6,h7)
end

local k64={"428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
	"3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
	"d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
	"72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
	"e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
	"2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
	"983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
	"c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
	"27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
	"650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
	"a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
	"d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
	"19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
	"391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
	"748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
	"90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
	"ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
	"06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
	"28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
	"4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"}

local k1, k2 = {}, {}

for _,v in next,k64 do
	k1[_]=tonumber(v:sub(1,8),16)
	k2[_]=tonumber(v:sub(9),16)
end




local beStrCuts64=function(s)
	local x,y,z={},{},1
	for i=1,16*8,8 do
		x[z] = beInt(s:sub(i,i+3))
		y[z] = beInt(s:sub(i+4,i+7))
		z = z + 1
	end
	return x, y
end

local function sum64(...)
	local q={...}
	local a, b = 0, 0
	for i = 1, #q, 2 do
		b = b + q[i + 1]
		if b >= 2^32 then
			local _ = b * .5^32
			a = a + _ - _ % 1
			b = b % 2^32
		end
		a = a + q[i]
	end
	if a >= 2 ^ 32 then
		a = a % 2^32
	end
	return a, b
end

function crypt.sha512(s)
	local msgLen=#s
	local padLen=112-msgLen%128
	if msgLen%128>112 then padLen=padLen+112 end
	if padLen==0 then padLen=128 end
	s=s.."\128"..("\0"):rep(padLen-1)
	s=s..beIstr(0)..beIstr(0)..beIstr(0)..beIstr(8*msgLen)
	assert(#s%128==0)
	local h11,h21,h31,h41,h51,h61,h71,h81=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
	local h12,h22,h32,h42,h52,h62,h72,h82=0xf3bcc908,0x84caa73b,0xfe94f82b,0x5f1d36f1,0xade682d1,0x2b3e6c1f,0xfb41bd6b,0x137e2179
	for _=1,#s,128 do
		local x, y=beStrCuts64(s:sub(_,_+127))
		for i=17,80 do
			local _1, _3 = i-2, i-15
			local _2, _4 = y[_1], y[_3]
			_1, _3 = x[_1], x[_3]
			local _5, _6 = rrotate64(_1,_2,19)
			_5, _6 = bxor64(_5, _6,rrotate64(_1,_2,61))
			local s00, s01=bxor64(_5, _6,rshift64(_1,_2,6))
			_5, _6 = rrotate64(_3,_4,1)
			_5, _6 = bxor64(_5,_6,rrotate64(_3,_4,8))
			local s10, s11=bxor64(_5,_6,rshift64(_3,_4,7))
			_1, _2 = i-7, i-16
			x[i], y[i] = sum64(x[_1],y[_1],s00,s01,x[_2],y[_2],s10,s11)
		end
		local a1,b1,c1,d1,e1,f1,g1,h1=h11,h21,h31,h41,h51,h61,h71,h81
		local a2,b2,c2,d2,e2,f2,g2,h2=h12,h22,h32,h42,h52,h62,h72,h82
		for i=1,80 do
			local _1, _2 = rrotate64(a1,a2,28)
			_1, _2 = bxor64(_1,_2,rrotate64(a1,a2,34))
			local s00,s01=bxor64(_1,_2,rrotate64(a1,a2,39))
			_1, _2 = rrotate64(e1,e2,14)
			_1, _2 = bxor64(_1,_2,rrotate64(e1,e2,18))
			local s10,s11=bxor64(_1,_2,rrotate64(e1,e2,41))
			_1,_2 = band64(e1,e2,f1,f2)
			local t11,t12=sum64(h1,h2,s10,s11,k1[i], k2[i],x[i], y[i],bxor64(_1,_2,band64(g1, g2, bnot64(e1,e2))))
			_1, _2 = band64(a1,a2,b1,b2)
			_3, _4 = band64(b1,b2,c1,c2)
			local t21,t22=sum64(s00,s01,bxor64(_1,_2,bxor64(_3,_4,band64(a1,a2,c1,c2))))
			h1,h2=g1,g2
			g1,g2=f1,f2
			f1,f2=e1,e2
			e1,e2=sum64(d1,d2,t11,t12)
			d1,d2=c1,c2
			c1,c2=b1,b2
			b1,b2=a1,a2
			a1,a2=sum64(t11,t12,t21,t22)
		end
		h11,h12=sum64(h11,h12,a1,a2)
		h21,h22=sum64(h21,h22,b1,b2)
		h31,h32=sum64(h31,h32,c1,c2)
		h41,h42=sum64(h41,h42,d1,d2)
		h51,h52=sum64(h51,h52,e1,e2)
		h61,h62=sum64(h61,h62,f1,f2)
		h71,h72=sum64(h71,h72,g1,g2)
		h81,h82=sum64(h81,h82,h1,h2)
	end
	return("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x"):format(h11,h12,h21,h22,h31,h32,h41,h42,h51,h52,h61,h62,h71,h72,h81,h82)
end

function crypt.sha384(s)
	local msgLen=#s
	local padLen=112-msgLen%128
	if msgLen%128>112 then padLen=padLen+112 end
	if padLen==0 then padLen=128 end
	s=s.."\128"..("\0"):rep(padLen-1)
	s=s..beIstr(0)..beIstr(0)..beIstr(0)..beIstr(8*msgLen)
	assert(#s%128==0)
	local h11,h21,h31,h41,h51,h61,h71,h81=0xcbbb9d5d,0x629a292a,0x9159015a,0x152fecd8,0x67332667,0x8eb44a87,0xdb0c2e0d,0x47b5481d
	local h12,h22,h32,h42,h52,h62,h72,h82=0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4
	for _=1,#s,128 do
		local x,y=beStrCuts64(s:sub(_,_+127))
		for i=17,80 do
			local _1,_3=i-2,i-15
			local _2,_4=y[_1],y[_3]
			_1,_3=x[_1],x[_3]
			local _5,_6=rrotate64(_1,_2,19)
			_5,_6=bxor64(_5,_6,rrotate64(_1,_2,61))
			local s00,s01=bxor64(_5,_6,rshift64(_1,_2,6))
			_5,_6=rrotate64(_3,_4,1)
			_5,_6=bxor64(_5,_6,rrotate64(_3,_4,8))
			local s10,s11=bxor64(_5,_6,rshift64(_3,_4,7))
			_5,_6=i-7,i-16
			x[i],y[i]=sum64(x[_5],y[_5],s00,s01,x[_6],y[_6],s10,s11)
		end
		local a1,b1,c1,d1,e1,f1,g1,h1=h11,h21,h31,h41,h51,h61,h71,h81
		local a2,b2,c2,d2,e2,f2,g2,h2=h12,h22,h32,h42,h52,h62,h72,h82
		for i=1,80 do
			local _1, _2 = rrotate64(a1,a2,28)
			_1, _2 = bxor64(_1,_2,rrotate64(a1,a2,34))
			local s00,s01=bxor64(_1,_2,rrotate64(a1,a2,39))
			_1, _2 = rrotate64(e1,e2,14)
			_1, _2 = bxor64(_1,_2,rrotate64(e1,e2,18))
			local s10,s11=bxor64(_1,_2,rrotate64(e1,e2,41))
			_1,_2 = band64(e1,e2,f1,f2)
			local t11,t12=sum64(h1,h2,s10,s11,k1[i], k2[i],x[i], y[i],bxor64(_1,_2,band64(g1, g2, bnot64(e1,e2))))
			_1, _2 = band64(a1,a2,b1,b2)
			_3, _4 = band64(b1,b2,c1,c2)
			local t21,t22=sum64(s00,s01,bxor64(_1,_2,bxor64(_3,_4,band64(a1,a2,c1,c2))))
			h1,h2=g1,g2
			g1,g2=f1,f2
			f1,f2=e1,e2
			e1,e2=sum64(d1,d2,t11,t12)
			d1,d2=c1,c2
			c1,c2=b1,b2
			b1,b2=a1,a2
			a1,a2=sum64(t11,t12,t21,t22)
		end
		h11,h12=sum64(h11,h12,a1,a2)
		h21,h22=sum64(h21,h22,b1,b2)
		h31,h32=sum64(h31,h32,c1,c2)
		h41,h42=sum64(h41,h42,d1,d2)
		h51,h52=sum64(h51,h52,e1,e2)
		h61,h62=sum64(h61,h62,f1,f2)
		h71,h72=sum64(h71,h72,g1,g2)
		h81,h82=sum64(h81,h82,h1,h2)
	end
	return("%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x"):format(h11,h12,h21,h22,h31,h32,h41,h42,h51,h52,h61,h62)
end

local st={0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13, 
	0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA, 
	0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12, 
	0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A, 
	0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
	0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03, 
	0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6, 
	0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1, 
	0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02, 
	0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F, 
	0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26, 
	0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52, 
	0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A, 
	0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39, 
	0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A, 
	0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14}

function crypt.md2(s)
	local msgLen=#s
	local padLen=-msgLen%16
	s=s..(chr(padLen)):rep(padLen)
	--assert(#s%16==0)
	do
		local c={}
		local l=0
		for i=1,#s,16 do
			local q=s:sub(i,i+15)
			for j=1,16 do
				c[j]=st[bxor8(q:byte(j),l)+1]
				l=c[j]
			end
		end
		for j=1,16 do
			s=s..chr(c[j])
		end
	end
	local x={}
	for i=1,#s,16 do
		local q=s:sub(i,i+15)
		for j=1,16 do
			x[16+j]=q:byte(j)
			x[32+j]=bxor8(x[16+j],x[j]or 0)
		end
		local t=0
		for j=1,18 do
			for k=1,48 do
				t=bxor8(x[k]or 0,st[t+1])
				x[k]=t
			end
			t=(t+j-1)%256
		end
	end
	return("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"):format(x[1],x[2],x[3],x[4],x[5],x[6],x[7],x[8],x[9],x[10],x[11],x[12],x[13],x[14],x[15],x[16])
end

local G=function (x,y,z) return bor(bor(band(x,y),band(x,z)),band(y,z)) end

function crypt.md4(s)
	local msgLen=#s
	local padLen=56-msgLen%64
	if msgLen%64>56 then padLen=padLen+64 end
	if padLen==0 then padLen=64 end
	s=s.."\128"..("\0"):rep(padLen-1)
	s=s..leIstr(8*msgLen)..leIstr(0)
	assert(#s%64==0)
	local a,b,c,d=0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476
	local A,B,C,D
	for _=1,#s,64 do
		local X=leStrCuts(s:sub(_,_+63))
		A,B,C,D=a,b,c,d

		a=z2(f,a,b,c,d,X[ 1], 3, 0)
		d=z2(f,d,a,b,c,X[ 2], 7, 0)
		c=z2(f,c,d,a,b,X[ 3],11, 0)
		b=z2(f,b,c,d,a,X[ 4],19, 0)
		a=z2(f,a,b,c,d,X[ 5], 3, 0)
		d=z2(f,d,a,b,c,X[ 6], 7, 0)
		c=z2(f,c,d,a,b,X[ 7],11, 0)
		b=z2(f,b,c,d,a,X[ 8],19, 0)
		a=z2(f,a,b,c,d,X[ 9], 3, 0)
		d=z2(f,d,a,b,c,X[10], 7, 0)
		c=z2(f,c,d,a,b,X[11],11, 0)
		b=z2(f,b,c,d,a,X[12],19, 0)
		a=z2(f,a,b,c,d,X[13], 3, 0)
		d=z2(f,d,a,b,c,X[14], 7, 0)
		c=z2(f,c,d,a,b,X[15],11, 0)
		b=z2(f,b,c,d,a,X[16],19, 0)

		a=z2(G,a,b,c,d,X[ 1], 3, 0x5A827999)
		d=z2(G,d,a,b,c,X[ 5], 5, 0x5A827999)
		c=z2(G,c,d,a,b,X[ 9], 9, 0x5A827999)
		b=z2(G,b,c,d,a,X[13],13, 0x5A827999)
		a=z2(G,a,b,c,d,X[ 2], 3, 0x5A827999)
		d=z2(G,d,a,b,c,X[ 6], 5, 0x5A827999)
		c=z2(G,c,d,a,b,X[10], 9, 0x5A827999)
		b=z2(G,b,c,d,a,X[14],13, 0x5A827999)
		a=z2(G,a,b,c,d,X[ 3], 3, 0x5A827999)
		d=z2(G,d,a,b,c,X[ 7], 5, 0x5A827999)
		c=z2(G,c,d,a,b,X[11], 9, 0x5A827999)
		b=z2(G,b,c,d,a,X[15],13, 0x5A827999)
		a=z2(G,a,b,c,d,X[ 4], 3, 0x5A827999)
		d=z2(G,d,a,b,c,X[ 8], 5, 0x5A827999)
		c=z2(G,c,d,a,b,X[12], 9, 0x5A827999)
		b=z2(G,b,c,d,a,X[16],13, 0x5A827999)

		a=z2(h,a,b,c,d,X[ 1], 3, 0x6ED9EBA1)
		d=z2(h,d,a,b,c,X[ 9], 9, 0x6ED9EBA1)
		c=z2(h,c,d,a,b,X[ 5],11, 0x6ED9EBA1)
		b=z2(h,b,c,d,a,X[13],15, 0x6ED9EBA1)
		a=z2(h,a,b,c,d,X[ 3], 3, 0x6ED9EBA1)
		d=z2(h,d,a,b,c,X[11], 9, 0x6ED9EBA1)
		c=z2(h,c,d,a,b,X[ 7],11, 0x6ED9EBA1)
		b=z2(h,b,c,d,a,X[15],15, 0x6ED9EBA1)
		a=z2(h,a,b,c,d,X[ 2], 3, 0x6ED9EBA1)
		d=z2(h,d,a,b,c,X[10], 9, 0x6ED9EBA1)
		c=z2(h,c,d,a,b,X[ 6],11, 0x6ED9EBA1)
		b=z2(h,b,c,d,a,X[14],15, 0x6ED9EBA1)
		a=z2(h,a,b,c,d,X[ 4], 3, 0x6ED9EBA1)
		d=z2(h,d,a,b,c,X[12], 9, 0x6ED9EBA1)
		c=z2(h,c,d,a,b,X[ 8],11, 0x6ED9EBA1)
		b=z2(h,b,c,d,a,X[16],15, 0x6ED9EBA1)

		a,b,c,d=(A+a)%2^32,(B+b)%2^32,(C+c)%2^32,(D+d)%2^32
	end
	return("%08x%08x%08x%08x"):format(swap(a),swap(b),swap(c),swap(d))
end

local  R={0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
	3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
	1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
	4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13}

local Rp={5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
	6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
	15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
	8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
	12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11}

local S={11,14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
	7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
	11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
	11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
	9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6}

local Sp={8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
	9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
	9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
	15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
	8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11}

function compare(t1,t2)
	if #t1~=#t2 then return false end
	for _,n in next,t1 do
		if t2[_]~=n then return false end
	end
	return true
end

function crypt.ripemd128(s)
	local msgLen=#s
	local padLen=56-msgLen%64
	if msgLen%64>56 then padLen=padLen+64 end
	if padLen==0 then padLen=64 end
	s=s.."\128"..("\0"):rep(padLen-1)
	s=s..leIstr(8*msgLen)..leIstr(0)
	assert(#s%64==0)
	local q=i
	local h1,h2,h3,h4=0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476
	for _=1,#s,64 do
		local X=leStrCuts(s:sub(_,_+63))
		local a,b,c,d=h1,h2,h3,h4
		local A,B,C,D,T=a,b,c,d
		for i=1,16 do
			T=(A+h(B,C,D)+X[i])%2^32
			A=D D=C C=B B=lrotate(T,S[i])

			T=(a+g(b,c,d)+X[Rp[i]+1]+0x50A28BE6)%2^32
			a=d d=c c=b b=lrotate(T,Sp[i])
		end

		for i=17,32 do
			T=(A+f(B,C,D)+X[R[i]+1]+0x5A827999)%2^32
			A=D D=C C=B B=lrotate(T,S[i])

			T=(a+q(b,d,c)+X[Rp[i]+1]+0x5C4DD124)%2^32
			a=d d=c c=b b=lrotate(T,Sp[i])
		end

		for i=33,48 do
			T=(A+q(B,D,C)+X[R[i]+1]+0x6ED9EBA1)%2^32
			A=D D=C C=B B=lrotate(T,S[i])

			T=(a+f(b,c,d)+X[Rp[i]+1]+0x6D703EF3)%2^32
			a=d d=c c=b b=lrotate(T,Sp[i])
		end

		for i=49,64 do
			T=(A+g(B,C,D)+X[R[i]+1]+0x8F1BBCDC)%2^32
			A=D D=C C=B B=lrotate(T,S[i])

			T=(a+h(b,c,d)+X[Rp[i]+1])%2^32
			a=d d=c c=b b=lrotate(T,Sp[i])
		end
		T=h2+C+d
		h2=h3+D+a
		h3=h4+A+b
		h4=h1+B+c
		h1=T
	end
	return("%08x%08x%08x%08x"):format(swap(h1),swap(h2),swap(h3),swap(h4))
end

function crypt.derive(userInput, length)
	local hashedInput = crypt.sha256(userInput)

	if #hashedInput < length then
		warn("Derived key length is longer than the hashed input.")
	end

	return hashedInput:sub(1, length)
end

return crypt
