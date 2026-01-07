local args = { ... }
if not args[1] then
    error("Requires a filename to execute",0)
end
local quickArgs = {}
do
    local prevArg
    for ind,i in ipairs(args) do
        if string.match(i,"^%-") then
            if prevArg then
                quickArgs[prevArg] = true
                prevArg = nil
            end
            prevArg = string.sub(i,2)
        elseif prevArg then
            quickArgs[prevArg] = tonumber(i) or i
            prevArg = nil
        end
    end
    if prevArg then
        quickArgs[prevArg] = true
        prevArg = nil
    end
end
local VM = {}

VM.ErrorCodes = {
    ERR_END_EXECUTION = 2,
    ERR_DIVISION_ZERO = 3,
    ERR_UNKNOWN_OPCODE = 4,
    ERR_INTERNAL_ERROR = 5,
    ERR_STACK_ERROR = 6,
    ERR_MEMORY_FAULT = 7,
    ERR_MEMBUS_FAULT = 8,
    ERR_WRITE_VIOLATION = 9,
    ERR_PORT_FAULT = 10,
    ERR_PAGE_VIOLATION = 11,
    ERR_READ_VIOLATION = 12,
    ERR_PROCESSOR_FAULT = 13,
    ERR_EXECUTE_VIOLATION = 14,
    ERR_ADDRESS_VIOLATION = 15,
    READ_REQUEST = 28,
    WRITE_REQUEST = 29,
    ERR_PAGE_TRAPPED = 30
}

do
    local reverse = {}
    for k,v in pairs(VM.ErrorCodes) do
        reverse[k] = v
        reverse[v] = k
    end
    VM.ErrorCodes = reverse
end

VM.Memory = {}
VM.MEMORY_MODEL = 65536
for i = 0, VM.MEMORY_MODEL do
    VM.Memory[i] = 0
end
VM.IP = 0
VM.XEIP = 0
VM.CMPR = 0
VM.IDTR = 0
VM.PTBE = 0
VM.PTBL = 0
VM.PCAP = 1
VM.interrupt_flag = 0
VM.interrupt_skip = 0
VM.LINT = 0
VM.LADD = 0
VM.cli_flag = 0
VM.extended_flag = 0
VM.extended_memory_flag = 0
VM.EAX, VM.EBX, VM.ECX, VM.EDX = 0, 0, 0, 0
VM.ESI, VM.EDI, VM.ESP, VM.EBP = 0, 0, VM.MEMORY_MODEL-1, 0
VM.CS, VM.SS, VM.DS, VM.ES, VM.GS, VM.FS, VM.KS, VM.LS = 0, 0, 0, 0, 0, 0, 0, 0
VM.ESZ = VM.ESP
VM.BLOCKSTART, VM.BLOCKSIZE = 0, 0
VM.PreqHandled = -1
VM.PreqOperand1 = 0
VM.PreqOperand2 = 0
VM.PreqReturn = 0
VM.R = {}
for i = 0, 31 do
    VM.R[i] = 0
end
VM.creation_time = os.clock()

VM.ExternalMemory = peripheral.wrap("address_bus") or _G.address_bus


local pages = {}
pages.proxies = {}
for i = 0, VM.MEMORY_MODEL / 128 do
   pages[i] = {
        disabled = 0, -- 0
        remapped = 0, -- 1
        trapped = 0, -- 2
        override = 0, -- 3
        unused = 0, -- 4
        read = 0, -- 5
        write = 0, -- 6
        execute = 0, -- 7
        runlevel = 0,
        map = 0
    }

    local idx = i
    local proxy = {}
    setmetatable(proxy, {
        __index = function(_, k)
            return pages[idx][k]
        end,
        __newindex = function(_, k, v)
            local page = pages[idx]
            local mask = 0
            page[k] = v

            if page.disabled ~= 0 then mask = mask + 1 end
            if page.remapped ~= 0 then mask = mask + 2 end
            if page.trapped ~= 0 then mask = mask + 4 end
            if page.override ~= 0 then mask = mask + 8 end
            if page.unused ~= 0 then mask = mask + 16 end
            if page.read ~= 0 then mask = mask + 32 end
            if page.write ~= 0 then mask = mask + 64 end
            if page.execute ~= 0 then mask = mask + 128 end
            mask = mask + page.runlevel * 256

            if idx >= VM.PTBE or idx < 0 then
                pageEntry = VM.PTBL
            else
                pageEntry = VM.PTBL + (idx + 1) * 2
            end

            VM.PCAP = 0
            VM:WriteCell(pageEntry, mask);
            VM:WriteCell(pageEntry + 1, page.map);
            VM.PCAP = 1
        end
    })
    
    pages.proxies[i] = proxy
end

VM.Pages = {}

setmetatable(VM.Pages, {
    __index = function(self, k)
        if VM.PCAP == 1 and VM.extended_memory_flag == 1 then
            local pageEntry

            if k >= VM.PTBE or k < 0 then
                pageEntry = VM.PTBL
            else
                pageEntry = VM.PTBL + (k + 1) * 2
            end

            VM.PCAP = 0
            local new_mask = VM:ReadCell(pageEntry)
            local new_map = VM:ReadCell(pageEntry + 1)
            VM.PCAP = 1            
            
            if VM.interrupt_flag ~= 0 then return end

            local page = pages[k]
            page.disabled = bit.band(new_mask, 1) ~= 0 and 1 or 0
            page.remapped = bit.band(new_mask, 2) ~= 0 and 1 or 0
            page.trapped = bit.band(new_mask, 4) ~= 0 and 1 or 0
            page.override = bit.band(new_mask, 8) ~= 0 and 1 or 0
            page.unused = bit.band(new_mask, 16) ~= 0 and 1 or 0
            page.read = bit.band(new_mask, 32) ~= 0 and 1 or 0
            page.write = bit.band(new_mask, 64) ~= 0 and 1 or 0
            page.execute = bit.band(new_mask, 128) ~= 0 and 1 or 0
            page.runlevel = math.floor(new_mask/256) % 256
            page.map = new_map

            return pages.proxies[k]
        end

        -- DefaultPage
        return {
            disabled = 0, -- 0
            remapped = 0, -- 1
            trapped = 0, -- 2
            override = 0, -- 3
            unused = 0, -- 4
            read = 0, -- 5
            write = 0, -- 6
            execute = 0, -- 7
            runlevel = 0,
            map = 0
        }
    end,

    __newindex = function()
    end
})

VM.CurrentPage = VM.Pages[0]
VM.PrevPage = VM.CurrentPage

local Instructions = {}

do
    local path = "/"..fs.combine(fs.getDir(shell.getRunningProgram()),"inst")
    local l = fs.list(path)
    for _,i in ipairs(l) do
        local req = require("inst."..i)
        for _,i in ipairs(req) do
            table.insert(Instructions,i)
        end
    end
end

local nInstructions = {}
local inst_env = {
    op1=0,
    op2=0,
    op1_set = error,
    op2_set = error,
}
local envmeta = {
    __index = function(self,k)
        local v = rawget(inst_env,k)
        if not v then
            return _ENV[k]
        end
        return v
    end,
    __newindex = function(self,k,v)
        local setter = inst_env[k.."_set"]
        if not setter then
            _ENV[k] = v
            return
        end
        setter(v)
    end
}
local fenv = setmetatable({},envmeta)

for ind,i in pairs(Instructions) do
    nInstructions[i[1]] = i
    setfenv(i[3],fenv)
end
Instructions = nInstructions

function VM:JMP(address, segment)
    segment = segment or self.CS
    address = address + segment
    if address < 0 or address >= VM.MEMORY_MODEL then
        self:int_vm(self.ErrorCodes.ERR_END_EXECUTION, address)
        return
    end
    self.CS = segment
    self.IP = address
end

function VM:CALL(address, segment)
    self:Push(self.IP)
    if self.interrupt_flag ~= 0 then return end
    self:JMP(address, segment)
end

function VM:int_vm(n, p)
    if self.cli_flag ~= 0 then
        self.interrupt_flag = n
        self.interrupt_skip = 1
        return
    end
    
    if self.extended_flag ~= 0 then
        local addr = self.IDTR + n * 4
        addr = math.max(0, math.min(addr, self.MEMORY_MODEL - 2))
        local ip = self:ReadCell(addr)
        local cs = self:ReadCell(addr + 1)
        local newptbl = self:ReadCell(addr + 2)
        local flags = self:ReadCell(addr + 3)

        if bit.band(flags, 32) ~= 0 then
            self:Push(self.IP)
            self:Push(self.CS)
            
            if bit.band(flags, 8) ~= 0 then
                self.CMPR = 1
            end
            
            if bit.band(flags, 16) ~= 0 then
                self:JMP(ip)
            else
                self:JMP(ip, cs)
            end
            
            if bit.band(flags, 128) ~= 0 then
                self.PTBL = newptbl
            end
            
            if bit.band(flags, 256) ~= 0 then
                self.PTBE = newptbl
            end
            
            if bit.band(flags, 512) ~= 0 then
                for i = 0, 30 do
                    self:Push(self.R[i])
                end
            end
            
            self.interrupt_skip = 1
        end
    end

    self.LINT = n
    self.LADD = p
    self.interrupt_flag = n
end

function VM:Push(n)
    self.ESP = self.ESP - 1
    local v = self:WriteCell(self.ESP + self.SS, n)
    if self.interrupt_flag ~= 0 then return end

    if self.ESP < 0 then
        self.ESP = 0
        self:int_vm(self.ErrorCodes.ERR_STACK_ERROR, self.ESP)
    end
end

function VM:Pop()
    self.ESP = self.ESP + 1
    
    if self.ESP > self.ESZ then
        self.ESP = self.ESZ
        self:int_vm(self.ErrorCodes.ERR_STACK_ERROR, self.ESP)
        return
    end

    return self:ReadCell(self.ESP + self.SS);
end

function VM:ReadCell(address)
    if address < 0 or address >= VM.MEMORY_MODEL then
        if VM.ExternalMemory then
            local v = VM.ExternalMemory:ReadCell(address-VM.MEMORY_MODEL)
            if not v or type(v) ~= "number" then
                self:int_vm(self.ErrorCodes.ERR_MEMORY_FAULT, address)
                return nil
            end
            return v
        else
            self:int_vm(self.ErrorCodes.ERR_MEMORY_FAULT, address)
            return nil
        end
    end
    
    if self.PCAP ~= 0 and self.extended_memory_flag ~= 0 then
        local index = math.floor(address / 128)
        local page = self.Pages[index]
        if self.interrupt_flag ~= 0 then return nil end

        if page.trapped == 1 then
            self:int_vm(self.ErrorCodes.ERR_PAGE_TRAPPED, address)
            return nil
        end

        if page.disabled ==1 then
            self:int_vm(self.ErrorCodes.ERR_MEMORY_FAULT, address)
            return nil
        end

        if self.extended_flag and self.CurrentPage.runlevel > page.runlevel and page.read == 0 then
            self:int_vm(self.ErrorCodes.ERR_READ_VIOLATION, address)
            return nil
        end 

        if page.remapped == 1 and page.map ~= index then
            address = address % 128 + page.map * 128
        end

        if page.override == 1 then
            if self.MEMRQ == 4 then
                self.MEMRQ = 0
                return self.LADD
            else
                self.MEMRQ = 2
                self.MEMADDR = address
                self.LADD = self.Memory[address]

                self:int_vm(self.ErrorCodes.READ_REQUEST, 0)
                return nil
            end
        end
    end

    return self.Memory[address]
end

function VM:WriteCell(address, value)
    if address < 0 or address >= VM.MEMORY_MODEL then
        if VM.ExternalMemory then
            local v = VM.ExternalMemory:WriteCell(address-VM.MEMORY_MODEL,value)
            if not v then
                self:int_vm(self.ErrorCodes.ERR_MEMORY_FAULT, address)
            end
            return
        else
            self:int_vm(self.ErrorCodes.ERR_MEMORY_FAULT, address)
            return
        end
    end

    if self.PCAP ~= 0 and self.extended_memory_flag ~= 0 then
        local index = math.floor(address / 128)
        local page = self.Pages[index]
        if self.interrupt_flag ~= 0 then return end

        if page.trapped == 1 then
            self:int_vm(self.ErrorCodes.ERR_PAGE_TRAPPED, address)
            return
        end

        if page.disabled ==1 then
            self:int_vm(self.ErrorCodes.ERR_MEMORY_FAULT, address)
            return
        end

        if page.override == 1 then
            if self.MEMRQ == 6 then
                self.MEMRQ = 0
                return
            elseif self.MEMRQ == 5 then
                self.MEMRQ = 0
                address = self.MEMADDR
                value = self.LADD

                self:int_vm(self.ErrorCodes.READ_REQUEST, 0)
                return
            else
                self.MEMRQ = 3
                self.MEMADDR = address
                self.LADD = value

                self:int_vm(self.ErrorCodes.WRITE_REQUEST, self.LADD)
                return
            end
        end

        if self.extended_flag and self.CurrentPage.runlevel > page.runlevel and page.write == 0 then
            self:int_vm(self.ErrorCodes.ERR_READ_VIOLATION, address)
            return
        end 

        if page.remapped == 1 and page.map ~= index then
            address = address % 128 + page.map * 128
        end
    end

    self.Memory[address] = value
end

function VM:fetch()
    local address = self.CS + self.IP
    if address < 0 or address >= VM.MEMORY_MODEL then
        self:int_vm(self.ErrorCodes.ERR_MEMORY_FAULT, address)
        return 0
    end
    local value = self.Memory[address]
    self.IP = self.IP + 1
    return value
end

function VM:GetOperand(rm, segment)
    local function memory_setter(addr)
        return function(value)
            self:WriteCell(addr, value)
        end
    end
    local function register_setter(index)
        return function(value)
            self:SetInternalRegister(index, value)
        end
    end

    if rm == 0 then
        local immediate = self:fetch()
        if self.interrupt_flag ~= 0 then return nil, nil end
        return immediate, function() end
    elseif rm <= 16 then
        local value = self:GetRegister(rm)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, register_setter(rm)
    elseif rm >= 17 and rm <= 24 then
        local reg = self:GetRegister(rm - 16)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local addr = reg
        local seg = segment == -1 and self.DS or self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = self:ReadCell(addr + seg)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, memory_setter(addr + seg)
    elseif rm == 25 then
        local addr = self:fetch()
        if self.interrupt_flag ~= 0 then return nil, nil end
        local seg = segment == -1 and self.DS or self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = self:ReadCell(addr + seg)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, memory_setter(addr + seg)
    elseif rm == 50 then
        local seg,ind = self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local immediate = self:fetch()
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = immediate + seg
        return value, register_setter(ind)
    elseif rm >= 2048 and rm <= 2079 then
        local index = rm - 2048
        return self.R[index], function(value) self.R[index] = value end
    elseif rm >= 2080 and rm <= 2111 then
        local addr = self.R[rm - 2080]
        local seg = segment == -1 and self.DS or self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = self:ReadCell(addr + seg)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, memory_setter(addr + seg)
    elseif rm >= 2144 and rm <= 2175 then
        local addr = self:fetch()
        if self.interrupt_flag ~= 0 then return nil, nil end
        local seg = segment == -1 and self.DS or self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = self:ReadCell(addr + seg)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, memory_setter(addr + seg)
    end
    
    self:int_vm(self.ErrorCodes.ERR_PROCESSOR_FAULT, rm)
    return nil, nil
end

function VM:GetRegister(index)
    local registers = {
        [1] = function() return self.EAX end,
        [2] = function() return self.EBX end,
        [3] = function() return self.ECX end,
        [4] = function() return self.EDX end,
        [5] = function() return self.ESI end,
        [6] = function() return self.EDI end,
        [7] = function() return self.ESP end,
        [8] = function() return self.EBP end,
        [9] = function() return self.CS end,
        [10] = function() return self.SS end,
        [11] = function() return self.DS end,
        [12] = function() return self.ES end,
        [13] = function() return self.GS end,
        [14] = function() return self.FS end,
        [15] = function() return self.KS end,
        [16] = function() return self.LS end
    }
    local reg = registers[index]
    if reg then return reg() end
    self:int_vm(self.ErrorCodes.ERR_PROCESSOR_FAULT, index)
    return nil
end

function VM:GetSegment(index)
    local segments = {
        [1] = function() return self.CS, 16 end,
        [2] = function() return self.SS, 17 end,
        [3] = function() return self.DS, 18 end,
        [4] = function() return self.ES, 19 end,
        [5] = function() return self.GS, 20 end,
        [6] = function() return self.FS, 21 end,
        [7] = function() return self.KS, 22 end,
        [8] = function() return self.LS, 23 end,
        [9] = function() return self.EAX, 1 end,
        [10] = function() return self.EBX, 2 end,
        [11] = function() return self.ECX, 3 end,
        [12] = function() return self.EDX, 4 end,
        [13] = function() return self.ESI, 5 end,
        [14] = function() return self.EDI, 6 end,
        [15] = function() return self.ESP, 7 end,
        [16] = function() return self.EBP, 8 end
    }
    if segments[index] then return segments[index]() end
    if index >= 17 and index <= 47 then return self.R[index - 17], index end
    self:int_vm(self.ErrorCodes.ERR_PROCESSOR_FAULT, index)
    return nil
end

function VM:GetInternalRegister(index)
    local registers = {
        [0] = self.IP,
        [1] = self.EAX,
        [2] = self.EBX,
        [3] = self.ECX,
        [4] = self.EDX,
        [5] = self.ESI,
        [6] = self.EDI,
        [7] = self.ESP,
        [8] = self.EBP,
        [9] = self.ESZ,
        [16] = self.CS,
        [17] = self.SS,
        [18] = self.DS,
        [19] = self.ES,
        [20] = self.GS,
        [21] = self.FS,
        [22] = self.KS,
        [23] = self.LS,
        [24] = self.IDTR,
        [25] = self.CMPR,
        [26] = self.XEIP,
        [27] = self.LADD,
        [28] = self.LINT,
        [29] = 0, -- TMR
        [30] = 0, -- TIMER
        [31] = 0, -- CPAGE
        [32] = self.interrupt_flag,
        [33] = 0, -- PF
        [34] = self.extended_flag,
        [35] = 0, -- NIF
        [36] = self.extended_memory_flag,
        [37] = self.PTBL,
        [38] = self.PTBE,
        [39] = self.PCAP,
        [40] = 0, -- RQCAP
        [41] = 0, -- PPAGE
        [42] = self.MEMRQ,
        [43] = self.MEMORY_MODEL,
        [44] = 0, -- External
        [45] = 0, -- Buslock
        [46] = 0, -- Idle
        [47] = 0, -- INTR
        [48] = 0, -- Serial Number
        [49] = 0, -- Code Bytes
        [50] = 0, -- BPREC
        [51] = 0, -- IPREC
        [52] = 0, -- NIDT
        [53] = self.BLOCKSTART,
        [54] = self.BLOCKSIZE,
        [55] = 0, -- VMODE
        [56] = 0, -- XTRL
        [57] = 0, -- HaltPort
        [58] = 0, -- HWDEBUG
        [59] = 0, -- DBGSTATE
        [60] = 0, -- DBGADDR
        [61] = 0, -- CRL
        [62] = 0, -- TIMERDT
        [63] = self.MEMADDR,
        [64] = 0, -- TimerMode
        [65] = 0, -- TimerRate
        [66] = 0, -- TimerPrevTime
        [67] = 0, -- TimerAddress
        [68] = 0, -- TimerPrevMode
        [69] = 0, -- LASTQUO
        [70] = 0, -- QUOFLAG
        [71] = self.PreqOperand1,
        [72] = self.PreqOperand2,
        [73] = self.PreqReturn,
        [74] = self.PreqHandled,
    }
    if registers[index] then return registers[index] end
    if index >= 96 and index <= 126 then return self.R[index - 17] end
    self:int_vm(self.ErrorCodes.ERR_PROCESSOR_FAULT, index)
    return 0
end

function VM:SetInternalRegister(index, value)
    local setters = {
        [0] = function(v) self:JMP(v, self.CS) end, -- IP
        [1] = function(v) self.EAX = v end,
        [2] = function(v) self.EBX = v end,
        [3] = function(v) self.ECX = v end,
        [4] = function(v) self.EDX = v end,
        [5] = function(v) self.ESI = v end,
        [6] = function(v) self.EDI = v end,
        [7] = function(v) self.ESP = v end,
        [8] = function(v) self.EBP = v end,
        [9] = function(v) self.ESZ = v end,
        [16] = function(v) self.CS = v end,
        [17] = function(v) self.SS = v end,
        [18] = function(v) self.DS = v end,
        [19] = function(v) self.ES = v end,
        [20] = function(v) self.GS = v end,
        [21] = function(v) self.FS = v end,
        [22] = function(v) self.KS = v end,
        [23] = function(v) self.LS = v end,
        [24] = function(v) self.IDTR = v end,
        [25] = function(v) self.CMPR = v end,
        [26] = function(v) end, -- XEIP
        [27] = function(v) self.LADD = v end,
        [28] = function(v) self.LINT = v end,
        [29] = function(v) end, -- TMR
        [30] = function(v) end, -- TIMER
        [31] = function(v) end, -- CPAGE
        [32] = function(v) self.interrupt_flag = v end,
        [33] = function(v) end, -- PF
        [34] = function(v) self.extended_flag = v end,
        [35] = function(v) end, -- NIF
        [36] = function(v) self.extended_memory_flag = v end,
        [37] = function(v) self.PTBL = v end,
        [38] = function(v) self.PTBE = v end,
        [39] = function(v) end, -- PCAP
        [40] = function(v) end, -- RQCAP
        [41] = function(v) end, -- PPAGE
        [42] = function(v) end, -- MEMRQ
        [43] = function(v) end, -- Memory Model
        [44] = function(v) end, -- External
        [45] = function(v) end, -- Buslock
        [46] = function(v) end, -- Idle
        [47] = function(v) end, -- INTR
        [48] = function(v) end, -- Serial Number
        [49] = function(v) end, -- Code Bytes
        [50] = function(v) end, -- BPREC
        [51] = function(v) end, -- IPREC
        [52] = function(v) end, -- NIDT
        [53] = function(v) self.BLOCKSTART = v end,
        [54] = function(v) self.BLOCKSIZE = v end,
        [55] = function(v) end, -- VMODE
        [56] = function(v) end, -- XTRL
        [57] = function(v) end, -- HaltPort
        [58] = function(v) end, -- HWDEBUG
        [59] = function(v) end, -- DBGSTATE
        [60] = function(v) end, -- DBGADDR
        [61] = function(v) end, -- CRL
        [62] = function(v) end, -- TIMERDT
        [63] = function(v) end, -- MEMADDR
        [64] = function(v) end, -- TimerMode
        [65] = function(v) end, -- TimerRate
        [66] = function(v) end, -- TimerPrevTime
        [67] = function(v) end, -- TimerAddress
        [68] = function(v) end, -- TimerPrevMode
        [69] = function(v) end, -- LASTQUO
        [70] = function(v) end, -- QUOFLAG
        [71] = function(v) self.PreqOperand1 = v end,
        [72] = function(v) self.PreqOperand2 = v end,
        [73] = function(v) self.PreqReturn = v end,
        [74] = function(v) self.PreqHandled = v end,
    }
    if setters[index] then
        setters[index](value)
    elseif index >= 96 and index <= 126 then
        self.R[index - 17] = value
    else
        self:int_vm(self.ErrorCodes.ERR_PROCESSOR_FAULT, index)
    end
end


function VM:step()
    if self.interrupt_flag ~= 0 then return end
    self.XEIP = self.IP
    self.PreviousPage = self.CurrentPage
    self.CurrentPage = self.Pages[math.floor(self.XEIP / 128)]
    if self.interrupt_flag ~= 0 then return end

    if self.PCAP ~= 0 and self.CurrentPage.execute == 0 and self.PreviousPage.runlevel > 0 then
        self:int_vm(self.ErrorCodes.ERR_EXECUTE_VIOLATION, self.IP)
        return
    end

    local opcode = self:fetch()
    if self.interrupt_flag ~= 0 then return end

    if (opcode >= 2000 and opcode < 4000) or (opcode >= 12000 and opcode < 14000) then
        opcode = opcode - 2000
    end

    local instr = Instructions[opcode%1000]
    if not instr then
        self:int_vm(self.ErrorCodes.ERR_UNKNOWN_OPCODE, opcode)
        return
    end

    if instr[2] == 0 and instr[3] then
        instr[3](self, 0, function() end)
        return
    end

    local rm = self:fetch()
    if self.interrupt_flag ~= 0 then return end

    local rm2 = math.floor(rm / 10000)
    local rm1 = rm - (rm2 * 10000)
    local segment1, segment2 = -1, -1

    if opcode > 1000 then
        if opcode > 10000 then
            segment2 = self:fetch()
            if self.interrupt_flag ~= 0 then return end
            opcode = opcode - 10000
            if opcode > 1000 then
                segment1 = self:fetch()
                if self.interrupt_flag ~= 0 then return end
                opcode = opcode - 1000
            end
        else
            segment1 = self:fetch()
            if self.interrupt_flag ~= 0 then return end
            opcode = opcode - 1000
        end
    end

    if instr[2] == 1 then
        local op1, op1_set = self:GetOperand(rm1, segment1)
        if self.interrupt_flag ~= 0 then return end
        inst_env.op1 = op1
        inst_env.op1_set = op1_set
    else
        local op1, op1_set = self:GetOperand(rm1, segment1)
        if self.interrupt_flag ~= 0 then return end
        local op2, op2_set = self:GetOperand(rm2, segment2)
        if self.interrupt_flag ~= 0 then return end
        inst_env.op1 = op1
        inst_env.op2 = op2
        inst_env.op1_set = op1_set
        inst_env.op2_set = op1_set
    end
    instr[3](self)
end


local filename = quickArgs.i
local files = {}
local file = fs.open(filename, "r")

if not file then
    error("No file found!", 2)
end

local content = file.readAll()
file.close()

content = content:gsub("db", "")
content = content:gsub("\n", "")
content = content:gsub("%s+", "")

local i = 0
for num in content:gmatch("[+-]?%d*%.?%d+") do
    VM.Memory[i] = tonumber(num)
    i = i + 1
end

term.clear()
if quickArgs.stepmode then
    print("Press any key to do a step.")
    while true do
        if VM.interrupt_flag ~= 0 then break end
        local e,c = os.pullEvent("char")
        --term.clear()
        VM:step()
        term.setCursorPos(1,1)
        print(string.format("IP: %d, EAX: %f, EBX: %f, ECX: %f, EDX: %f, ESI: %f, EDI: %f, ESP: %f", VM.IP, VM.EAX, VM.EBX, VM.ECX, VM.EDX, VM.ESI, VM.EDI, VM.ESP))
        -- print("\n\n",c)
    end
else
    local time = os.clock()
    local ips = 0
    while VM.interrupt_flag == 0 do
        VM:step()
        ips = ips + 1
        if os.clock()-time > 1 then
            print("IPS:",ips)
            ips = 0
            time = os.clock()
            sleep(0.05)
        end
        --term.setCursorPos(1,1)
        -- sleep(0.05)
        --print(string.format("IP: %d, EAX: %f, EBX: %f, ECX: %f, EDX: %f, ESI: %f, EDI: %f, ESP: %f", VM.IP, VM.EAX, VM.EBX, VM.ECX, VM.EDX, VM.ESI, VM.EDI, VM.ESP))
    end
end
end

error("Error: " .. VM.interrupt_flag .. "("..VM.ErrorCodes[VM.interrupt_flag]..")" .. " " .. VM.LADD,0)
