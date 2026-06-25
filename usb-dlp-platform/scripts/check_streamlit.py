import importlib.util
spec = importlib.util.find_spec('streamlit')
print('FOUND' if spec else 'MISSING')
