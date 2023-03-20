local function string_to_array(strings)
    local result = {}
    for str in string.gmatch(strings, "[A-Z]+,") do
        table.insert(result, string.sub(str,0,string.len(str) - 1))
    end
    return result
end

return {
    string_to_array = string_to_array,
}
