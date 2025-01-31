# %%
pip install scikit-learn

# %%
import numpy as np
import pandas as pd
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

import numpy as np
import pandas as pd
import re
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score


def extract_features(data: list) -> list:
    features = []
    for snippet in data:
        lines = snippet.split('\n')
        num_lines = len(lines)
        avg_line_length = sum([len(line) for line in lines]) / num_lines
        num_semicolons = sum([line.count(';') for line in lines])
        num_special_chars = sum([len(re.findall(r'[{}()\[\]#\\+*/%=]', line)) for line in lines])
        num_keywords = sum([len(re.findall(r'\b(if|else|for|while|do|break|continue|default|return|int|char|float|void)\b', line)) for line in lines])
        num_comments = sum([1 for line in lines if line.startswith('//') or '/*' in line or '*/' in line])
        num_numeric_values = sum([len(re.findall(r'\b\d+\b', line)) for line in lines])
        num_words = sum([len(re.findall(r'\b\w+\b', line)) for line in lines])
        ratio_numeric_words = num_numeric_values / num_words if num_words > 0 else 0
        features.append([num_lines, avg_line_length, num_semicolons, num_special_chars, num_keywords, num_comments, ratio_numeric_words])
    return features

# Function that will read the data from the file and return the data in the form of a list
def read_data(file_path: str, delimiter: str) -> list:
    with open(file_path, 'r', errors='ignore') as file:
        data = file.read().split(delimiter)
    return data


# Read the data from the files
c_data = read_data('combined_code.txt', delimiter='THISISENDOFCODE')
text_data = read_data('aggregated_text.txt', delimiter='THISISENDOFENTRY')

# Create labels for the data
c_labels = [1] * len(c_data)
text_labels = [0] * len(text_data)

# Combine the data and labels
data = c_data + text_data
labels = c_labels + text_labels
print(f"Total number of snippets: {len(data)}")
print("generating features...")
features = np.array(extract_features(data))


# %%
#write to features.txt file all the features vectors and the label one each line
with open('features.txt', 'w') as file:
    for i in range(len(features)):
        file.write(f"{features[i][0]} {features[i][1]} {features[i][2]} {features[i][3]} {features[i][4]} {features[i][5]} {features[i][6]} {labels[i]}\n")

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
x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, stratify=labels)

model = SVC(class_weight='balanced', random_state=42)
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

print(f"Accuracy: {accuracy_score(y_test, y_pred)}")



