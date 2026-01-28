module FINGERPRINT;

export {
    # Format a vector of count type to a string type
    global vector_of_count_to_str: function (input: vector of count, format_str: string &default="%04x", 
        dlimit: string &default=",",  skip: set[count] &default=set()): string;

    # Format a vector of string type to a string type
    global vector_of_str_to_str: function (input: vector of string, format_str: string &default="%s", 
        dlimit: string &default=","): string;

    # Sort a vector of count by the count values
    global order_vector_of_count: function (input: vector of count): vector of count;

    # Produce the hash value (or 000000000000 for empty string)
    global sha256_or_null__12: function (input: string): string;

}

# Format a vector of count type to a string type
function vector_of_count_to_str(input: vector of count, format_str: string &default="%04x", 
    dlimit: string &default=",", skip: set[count] &default=set()): string {
    local output = "";
    for (idx in input) {
        local val = input[idx];
        if (val in skip) {
            next;
        }
        output += fmt(format_str, val);
        if (idx < |input|-1) {
        output += dlimit;
        }
    }
    return output;
}

# Format a vector of string type to a string type
function vector_of_str_to_str(input: vector of string, format_str: string &default="%s", 
    dlimit: string &default=","): string {
    local output = "";
    for (idx in input) {
        local val = input[idx];
        output += fmt(format_str, val);
        if (idx < |input|-1) {
        output += dlimit;
        }
    }
    return output;
}

# Sort a vector of count by the count values
function order_vector_of_count(input: vector of count): vector of count {
    local outvec = copy(input);
    sort(outvec, function(a: count, b: count): int {
        if ( a < b ) return -1;
        if ( a > b ) return 1;
        return 0;
    });
    return outvec;
}

# Produce the hash value (or 000000000000 for empty string)
function sha256_or_null__12(input: string): string {
    if (input == "") {
        return "000000000000";
    }
    local sha256_object = sha256_hash_init();
    sha256_hash_update(sha256_object, input);
    return sha256_hash_finish(sha256_object)[:12];
}

