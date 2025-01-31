# %%

# %%
import numpy as np
import re
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
import pickle

# %%
# in this file, we will implement a model to distinguish between C code and Plain text.
# we will use the SVC model to classify the code snippets.
# In the training data, we have 2 classes: 0 for Plain text and 1 for C code.
# To train the data we will extract the features from the code snippets.
# The features we will use are:
# 1. Number of lines (will be used to calculate other features)
# 2. Average line length
# 3. Number of semicolons
# 4. Number of special characters, such as {}, (), [], #, /, \, +, -, *, %, =
# 5. Number of keywords such as if, else, for, while, do, break, continue, default, return, int, char, float
# 6. Number of comments i.e. lines starting with // or containing /* or */
# 7. Ratio of numeric values to the number of words

# %%
# load the features from the file. each line is a feature where the last element is the label and the rest are the features
with open('features.txt', 'r') as file:
    features = []
    labels = []
    for line in file:
        line = line.strip()
        features.append([float(x) for x in line.split()[:-1]])
        labels.append(int(line.split()[-1]))

# %%
x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)


print("features len: ", len(x_train), " ", len(x_test))
print("labels len: ", len(y_train), " ", len(y_test))


model = SVC(class_weight='balanced')
# x_combined = np.vstack((x_train, x_test))
# y_combined = np.concatenate((y_train, y_test))
print("Training the model...")
model.fit(x_train, y_train)

print("Model trained successfully.")

# Save the model
filename = 'tester_from_extractor.sav'
pickle.dump(model, open(filename, 'wb'))

# load the model from disk
loaded_model = pickle.load(open(filename, 'rb'))

# Evaluate the model
y_pred = loaded_model.predict(x_test)

conf_matrix = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(conf_matrix)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("Accuracy: ", accuracy_score(y_test, y_pred))


