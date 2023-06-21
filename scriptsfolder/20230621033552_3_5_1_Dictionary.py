# Ordered, Changeble and not allow duplication

x = {"Ram":24,"Rahul":12,"Karan":18}
c = x.get("Rahul")
print(c)


dict = {"Apple":"Red","Banana":"Yellow","Grape":"White"}
# Store the values of dictionary in list
k = dict.values()
print(k)
# Change the value of particular key 
dict["Grape"] = "Green"
print(dict) 

# Add new pair in dictionary
dict["Watermelon"] = "Green"
print(dict)
