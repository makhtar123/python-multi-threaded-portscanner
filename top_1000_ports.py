list_from_file = open("common_ports.txt").read().split(',')

def expand_ranges(input_list):
    expanded_list = []
    
    for item in input_list:
        # 1. Clean the data: Convert to string and remove spaces/newlines
        s_item = str(item).strip()
        
        # 2. Skip empty items (caused by trailing commas or empty lines in files)
        if not s_item:
            continue

        try:
            if '-' in s_item:
                parts = s_item.split('-')
                
                # Check if we have exactly 2 parts and neither is empty
                if len(parts) == 2 and parts[0] and parts[1]:
                    start = int(parts[0])
                    end = int(parts[1])
                    rng = range(start, end + 1)
                    expanded_list.extend(rng)
                else:
                    print(f"Skipping malformed range: '{s_item}'")
            else:
                expanded_list.append(int(s_item))
                
        except ValueError as e:
            print(f"Error processing item '{s_item}': {e}")
            # We continue the loop so the program doesn't crash completely
            continue
            
    return expanded_list

common_ports = expand_ranges(list_from_file)
