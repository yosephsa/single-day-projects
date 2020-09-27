'''
    File name: make-csv.py
    Author: Yoseph Alabdulwahab
    Date created: 9/26/2020
    Python Version: 3.8.5
    Purpose: Pre process raw email data into csv file in a format
    			for neural network spam classifier.
'''

import csv
import os
import codecs

BASE_DIR = os.path.abspath("")
CSV_COLUMNS = ["id", "content", "isSpam"]

def main():
	dirData = os.path.join(BASE_DIR, "datasets")
	
	# Select spam datasets
	dirsTrain = []
	for i in range(1, 7):
		dirsTrain.append(os.path.join(dirData, "raw", "enron"+str(i), "spam"))
		dirsTrain.append(os.path.join(dirData, "raw", "enron"+str(i), "ham"))

	
	# Select CSV files
	fpTrain = os.path.join(dirData, "training.csv")


	#create file and write first row (column names)
	processRawInto(dirsTrain, os.path.join(dirData, "training.csv"))
	
	

	return

def processRawInto(dirArr, filePath, min = None, max = None):
	file = open(filePath,"w+")
	writeArrayTo(file, CSV_COLUMNS)

	lastIndex = -1
	#loop through given directory array and write file contents to csv
	for directory in dirArr:
		for eaFile in os.listdir(directory):
			lastIndex += 1
			#skip values below min if min is set
			if(isinstance(min, int) and lastIndex < min):
				continue
			filename = os.fsdecode(eaFile)
			#Set isSpam value
			isSpam = ""
			if filename.endswith(".spam.txt"):
				isSpam = "True"
			if filename.endswith(".ham.txt"):
				isSpam = "False"
			#Get content and write to file
			rawFile = open(file=os.path.join(directory, filename), mode="r", encoding='utf-8', errors='ignore')
			rawContent = rawFile.read()
			rawContent = rawContent.replace(',', 'U+002C')
			rawContent = rawContent.replace('\n', 'U+2424')
			writeArrayTo(file, [str(lastIndex), rawContent, isSpam])

			#print index
			print(str(lastIndex) + "\n")
			#skip values above max is max is set
			if(isinstance(max, int) and lastIndex >= max):
				break
	file.close()



def writeArrayTo(file, arr):
	for r in range(len(arr)): 
		if(r == 0):
			file.write(arr[r])
		else:
			file.write("," + arr[r])
	file.write("\n")

main()
