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

BASE_DIR = os.path.abspath("")

def main():
	dirData = os.path.join(BASE_DIR, "datasets")
	dirSpam = os.path.join(dirData, "raw", "spam")
	dirHam = os.path.join(dirData, "raw", "ham")

	fileCSV = os.path.join(dirData, "training.csv")

main()
