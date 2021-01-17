ceiling = 1000
index = 0
sum = 0

while index < ceiling:
	if index % 3 == 0:
		sum += index
	elif index % 5 == 0:
		sum += index
	index += 1
print(sum)