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
lastIndex = 0

def main():
	dirData = os.path.join(BASE_DIR, "datasets")
	# Select datasets
	dirSpam1 = os.path.join(dirData, "raw", "enron1", "spam")
	dirHam1 = os.path.join(dirData, "raw", "enron1", "ham")

	dirSpam2 = os.path.join(dirData, "raw", "enron2", "spam")
	dirHam2 = os.path.join(dirData, "raw", "enron2", "ham")

	dirSpam3 = os.path.join(dirData, "raw", "enron3", "spam")
	dirHam3 = os.path.join(dirData, "raw", "enron3", "ham")

	dirSpam4 = os.path.join(dirData, "raw", "enron4", "spam")
	dirHam4 = os.path.join(dirData, "raw", "enron4", "ham")

	dirSpam5 = os.path.join(dirData, "raw", "enron5", "spam")
	dirHam5 = os.path.join(dirData, "raw", "enron5", "ham")

	dirSpam6 = os.path.join(dirData, "raw", "enron6", "spam")
	dirHam6 = os.path.join(dirData, "raw", "enron6", "ham")

	
	# Select CSV files
	fpTrain = os.path.join(dirData, "training.csv")

	#Create train array and test array
	dirTrainArr = [dirSpam1, dirHam1, dirSpam2, dirHam2, dirSpam3, dirHam3, dirSpam4, dirHam4, dirSpam5, dirHam5, dirSpam6, dirHam6]
	#dirTrainArr = [dirSpam1]
	dirTestArr = [dirSpam5, dirHam5, dirSpam6, dirHam6]

	#create file and write first row (column names)
	fTrain = open(fpTrain,"w+")
	writeArrayTo(fTrain, CSV_COLUMNS)

	#Process given raw data into given file 
	processRawInto(dirTrainArr, fTrain)

	fTrain.close()
	return

def processRawInto(dirArr, file, min = None, max = None):
	global lastIndex
	lastIndex -= 1

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



def writeArrayTo(file, arr):
	for r in range(len(arr)): 
		if(r == 0):
			file.write(arr[r])
		else:
			file.write("," + arr[r])
	file.write("\n")

main()
