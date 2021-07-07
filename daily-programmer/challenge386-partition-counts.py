
def countPartitions(number):
	if(number == 0):
		return 1
	elif(number == 1):
		return 1

	partitions = 0;
	half=number/2
	i = 1
	while i < half:
		partitions += 1 + countPartitions(number - i)
		i+=1

	return partitions

print(countPartitions(24))