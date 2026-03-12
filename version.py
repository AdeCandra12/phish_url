import sys, platform
import numpy as np, sklearn, joblib, pandas, streamlit

print("Python   :", sys.version.split()[0])
print("NumPy    :", np.__version__)
print("sklearn  :", sklearn.__version__)
print("joblib   :", joblib.__version__)
print("pandas   :", pandas.__version__)
print("streamlit:", streamlit.__version__)
print("OS       :", platform.platform())
