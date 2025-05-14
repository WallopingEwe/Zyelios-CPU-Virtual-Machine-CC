local VM = {}
local Instructions = {
    { 0, 0, END },
    { 1, 1, JNE },
    { 2, 1, JMP },
    { 3, 1, JG },
    { 4, 1, JGE },
    { 5, 1, JL },
    { 6, 1, JLE },
    { 7, 1, JE },
    { 8, 0, CPUID },
    { 9, 1, PUSH },
    { 10, 2, ADD },
    { 11, 2, SUB },
    { 12, 2, MUL },
    { 13, 2, DIV },
    { 14, 2, MOV },
    { 15, 2, CMP },
    { 50, 2, AND },
    { 51, 2, OR },
    { 52, 2, XOR },
    { 64, 2, BAND },
    { 65, 2, BOR },
    { 66, 2, BXOR },
    { 67, 2, BSHL },
    { 68, 2, BSHR }
}

-- Error codes
local ErrorCodes = {
    ERR_END_EXECUTION = 2,
    ERR_DIVISION_ZERO = 3,
    ERR_UNKNOWN_OPCODE = 4,
    ERR_INTERNAL_ERROR = 5,
    ERR_STACK_ERROR = 6,
    ERR_MEMORY_FAULT = 7,
    ERR_PROCESSOR_FAULT = 13
}

VM.Memory = {}
for i = 0, 511 do
    VM.Memory[i] = 0
end
VM.IP = 0
VM.XEIP = 0
VM.CMPR = 0
VM.IDTR = 0
VM.PTBE = 0
VM.PTBL = 0
VM.interrupt_flag = 0
VM.interrupt_skip = 0
VM.LINT = 0
VM.LADD = 0
VM.cli_flag = 0
VM.extended_flag = 0
VM.extended_memory_flag = 0
VM.EAX, VM.EBX, VM.ECX, VM.EDX = 0, 0, 0, 0
VM.ESI, VM.EDI, VM.ESP, VM.EBP = 0, 0, 511, 0
VM.CS, VM.SS, VM.DS, VM.ES, VM.GS, VM.FS, VM.KS, VM.LS = 0, 0, 0, 0, 0, 0, 0, 0
VM.ESZ = 0
VM.R = {}
for i = 0, 31 do
    VM.R[i] = 0
end
VM.immediate_swap = 0
VM.creation_time = os.clock()

-- Instruction implementations
function END(vm, op1, op1_set)
    vm:int_vm(ErrorCodes.ERR_END_EXECUTION, 0)
end

function JNE(vm, op1, op1_set)
    if vm.CMPR ~= 0 then
        vm:JMP(op1, vm.CS)
    end
end

function JMP(vm, op1, op1_set)
    vm:JMP(op1, vm.CS)
end

function JG(vm, op1, op1_set)
    if vm.CMPR > 0 then
        vm:JMP(op1, vm.CS)
    end
end

function JGE(vm, op1, op1_set)
    if vm.CMPR >= 0 then
        vm:JMP(op1, vm.CS)
    end
end

function JL(vm, op1, op1_set)
    if vm.CMPR < 0 then
        vm:JMP(op1, vm.CS)
    end
end

function JLE(vm, op1, op1_set)
    if vm.CMPR <= 0 then
        vm:JMP(op1, vm.CS)
    end
end

function JE(vm, op1, op1_set)
    if vm.CMPR == 0 then
        vm:JMP(op1, vm.CS)
    end
end

function CPUID(vm, op1, op1_set)
    vm:SetInternalRegister(1, 1) -- Set EAX to some CPU identifier
end

function PUSH(vm, op1, op1_set)
    vm:Push(op1)
end

function ADD(vm, op1, op1_set, op2, op2_set)
    op1_set(op1 + op2)
end

function SUB(vm, op1, op1_set, op2, op2_set)
    op1_set(op1 - op2)
end

function MUL(vm, op1, op1_set, op2, op2_set)
    op1_set(op1 * op2)
end

function DIV(vm, op1, op1_set, op2, op2_set)
    if op2 == 0 then
        vm:int_vm(ErrorCodes.ERR_DIVISION_ZERO, 0)
        return
    end
    op1_set(op1 / op2)
end

function MOV(vm, op1, op1_set, op2, op2_set)
    op1_set(op2)
end

function CMP(vm, op1, op1_set, op2, op2_set)
    vm.CMPR = op1 - op2
end

function AND(vm, op1, op1_set, op2, op2_set)
    op1_set((op1 ~= 0 and op2 ~= 0) and 1.0 or 0.0)
end

function OR(vm, op1, op1_set, op2, op2_set)
    op1_set((op1 ~= 0 or op2 ~= 0) and 1.0 or 0.0)
end

function XOR(vm, op1, op1_set, op2, op2_set)
    op1_set(((op1 ~= 0) ~= (op2 ~= 0)) and 1.0 or 0.0)
end

function BAND(vm, op1, op1_set, op2, op2_set)
    op1_set(bit.band(math.floor(op1), math.floor(op2)))
end

function BOR(vm, op1, op1_set, op2, op2_set)
    op1_set(bit.bor(math.floor(op1), math.floor(op2)))
end

function BXOR(vm, op1, op1_set, op2, op2_set)
    op1_set(bit.bxor(math.floor(op1), math.floor(op2)))
end

function BSHL(vm, op1, op1_set, op2, op2_set)
    op1_set(bit.lshift(math.floor(op1), math.floor(op2)))
end

function BSHR(vm, op1, op1_set, op2, op2_set)
    op1_set(bit.rshift(math.floor(op1), math.floor(op2)))
end

function VM:JMP(address, segment)
    address = address + segment
    if address < 0 or address >= 512 then
        self:int_vm(ErrorCodes.ERR_END_EXECUTION, address)
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
        addr = math.max(0, math.min(addr, 510))
        
        local ip = self:ReadCell(addr, 0)
        local cs = self:ReadCell(addr + 1, 0)
        local newptbl = self:ReadCell(addr + 2, 0)
        local flags = self:ReadCell(addr + 3, 0)

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
    local address = self.ESP + self.SS
    if self.ESP == self.SS or address < 0 or address >= 512 then
        self:int_vm(ErrorCodes.ERR_STACK_ERROR, n)
        return
    end
    self.Memory[address] = n
    self.ESP = self.ESP - 1
end

function VM:Pop()
    self.ESP = self.ESP + 1
    local address = self.ESP + self.SS
    if address < 0 or address >= 512 then
        self:int_vm(ErrorCodes.ERR_STACK_ERROR, address)
        return nil
    end
    return self.Memory[address]
end

function VM:ReadCell(address, segment)
    address = address + segment
    if address < 0 or address >= 512 then
        self:int_vm(ErrorCodes.ERR_MEMORY_FAULT, address)
        return nil
    end
    return self.Memory[address]
end

function VM:WriteCell(address, segment, value)
    address = address + segment
    if address < 0 or address >= 512 then
        self:int_vm(ErrorCodes.ERR_MEMORY_FAULT, address)
        return
    end
    self.Memory[address] = value
end

function VM:fetch()
    local address = self.CS + self.IP
    if address < 0 or address >= 512 then
        self:int_vm(ErrorCodes.ERR_MEMORY_FAULT, address)
        return 0
    end
    local value = self.Memory[address]
    self.IP = self.IP + 1
    return value
end

function VM:GetOperand(rm, segment)
    local function memory_setter(addr, seg)
        return function(value)
            self:WriteCell(addr, seg, value)
        end
    end
    local function register_setter(index)
        return function(value)
            self:SetInternalRegister(index, value)
        end
    end

    if rm == 0 then
        self.immediate_swap = not self.immediate_swap
        self.immediates = self.immediates or {}
        self.immediates[self.immediate_swap and 1 or 2] = self:fetch()
        if self.interrupt_flag ~= 0 then return nil, nil end
        -- Immediate values are read-only
        return self.immediates[self.immediate_swap and 1 or 2], function() end
    elseif rm <= 16 then
        local value = self:GetRegister(rm)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, register_setter(rm)
    elseif rm >= 17 and rm <= 24 then
        local reg = self:GetRegister(rm - 16)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local addr = reg
        local seg = segment == -1 and 0 or self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = self:ReadCell(addr, seg)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, memory_setter(addr, seg)
    elseif rm == 25 then
        local addr = self:fetch()
        if self.interrupt_flag ~= 0 then return nil, nil end
        local seg = segment == -1 and 0 or self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = self:ReadCell(addr, seg)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, memory_setter(addr, seg)
    elseif rm == 50 then
        local seg = self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local immediate = self:fetch()
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = immediate + seg
        -- Computed address is read-only
        return value, function() end
    elseif rm >= 2048 and rm <= 2079 then
        local index = rm - 2048
        return self.R[index], function(value) self.R[index] = value end
    elseif rm >= 2080 and rm <= 2111 then
        local addr = self.R[rm - 2080]
        local seg = segment == -1 and 0 or self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = self:ReadCell(addr, seg)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, memory_setter(addr, seg)
    elseif rm >= 2144 and rm <= 2175 then
        local addr = self:fetch()
        if self.interrupt_flag ~= 0 then return nil, nil end
        local seg = segment == -1 and 0 or self:GetSegment(segment)
        if self.interrupt_flag ~= 0 then return nil, nil end
        local value = self:ReadCell(addr, seg)
        if self.interrupt_flag ~= 0 then return nil, nil end
        return value, memory_setter(addr, seg)
    end
    self:int_vm(ErrorCodes.ERR_PROCESSOR_FAULT, 0)
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
    self:int_vm(ErrorCodes.ERR_PROCESSOR_FAULT, index)
    return nil
end

function VM:GetSegment(index)
    local segments = {
        [1] = function() return self.CS end,
        [2] = function() return self.SS end,
        [3] = function() return self.DS end,
        [4] = function() return self.ES end,
        [5] = function() return self.GS end,
        [6] = function() return self.FS end,
        [7] = function() return self.KS end,
        [8] = function() return self.LS end,
        [9] = function() return self.EAX end,
        [10] = function() return self.EBX end,
        [11] = function() return self.ECX end,
        [12] = function() return self.EDX end,
        [13] = function() return self.ESI end,
        [14] = function() return self.EDI end,
        [15] = function() return self.ESP end,
        [16] = function() return self.EBP end
    }
    if segments[index] then return segments[index]() end
    if index >= 17 and index <= 47 then return self.R[index - 17] end
    self:int_vm(ErrorCodes.ERR_PROCESSOR_FAULT, index)
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
        [32] = self.interrupt_flag,
        [34] = self.extended_flag,
        [36] = self.extended_memory_flag,
        [37] = self.PTBL,
        [38] = self.PTBE
    }
    if registers[index] then return registers[index] end
    if index >= 96 and index <= 126 then return self.R[index - 17] end
    self:int_vm(ErrorCodes.ERR_PROCESSOR_FAULT, index)
    return 0
end

function VM:SetInternalRegister(index, value)
    local setters = {
        [0] = function(v) self:JMP(v, self.CS) end,
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
        [27] = function(v) self.LADD = v end,
        [28] = function(v) self.LINT = v end,
        [32] = function(v) self.interrupt_flag = v end,
        [34] = function(v) self.extended_flag = v end,
        [36] = function(v) self.extended_memory_flag = v end,
        [37] = function(v) self.PTBL = v end,
        [38] = function(v) self.PTBE = v end
    }
    if setters[index] then
        setters[index](value)
    elseif index >= 96 and index <= 126 then
        self.R[index - 17] = value
    else
        self:int_vm(ErrorCodes.ERR_PROCESSOR_FAULT, index)
    end
end

function VM:step()
    if self.interrupt_flag ~= 0 then return end
    self.XEIP = self.IP
    local opcode = self:fetch()
    if self.interrupt_flag ~= 0 then return end

    if (opcode >= 2000 and opcode < 4000) or (opcode >= 12000 and opcode < 14000) then
        opcode = opcode - 2000
    end

    local instr = nil
    for i = 1, #Instructions do
        if Instructions[i][1] == opcode then
            instr = Instructions[i]
            break
        end
    end

    if not instr then
        self:int_vm(ErrorCodes.ERR_UNKNOWN_OPCODE, opcode)
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
        instr[3](self, op1, op1_set)
    else
        local op1, op1_set = self:GetOperand(rm1, segment1)
        if self.interrupt_flag ~= 0 then return end
        local op2, op2_set = self:GetOperand(rm2, segment2)
        if self.interrupt_flag ~= 0 then return end
        instr[3](self, op1, op1_set, op2, op2_set)
    end
end