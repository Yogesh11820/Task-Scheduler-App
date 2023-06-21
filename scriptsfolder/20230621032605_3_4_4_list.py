msg = ["hello","good","morning"]
print(msg[0])

# Negative Indexing  --> starts from -1 from right to left
print(msg[-1])    

# Accessing multiple elements
print(msg[0:2])
print(msg[-3:-1])

# Check if element is present in list or not
if "good" in msg:
    print("good is present in msg")

# Change value of particular index
msg[2] = "Night"
print(msg)

#list can contain different types of datatypes --> flexible and dynamic manupulation of data
dynamic_list = [2,4,8.9,'aero',[1,2,3]]
print(dynamic_list)
