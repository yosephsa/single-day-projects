cap = 4_000_000
i = 2 #current fib num
j = 1 #previous fib num
sum = 0

while i < cap:
	if(i % 2 == 0): #Only sum even values of fibinnaci
		sum += i; #sum current i

	#i Calc and Var Swap
	temp = i #hold i temporarily
	i += j #calculate new fib num
	j = temp #update j to old i

print(sum)