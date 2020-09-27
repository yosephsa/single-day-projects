'''
    File name: main.py
    Author: Yoseph Alabdulwahab
    Date created: 9/26/2020
    Python Version: 3.8.5
    Purpose: Classify emails as Spam or Ham(not spam) using a neural network.
'''

import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn import svm
from sklearn.neural_network import MLPClassifier
#from sklearn.linear_model import SGDClassifier
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

