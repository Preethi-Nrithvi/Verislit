import streamlit as st
from explain import explain

st.title("Verislit")
st.write("Got a confusing or scary message? Upload a screenshot or paste the text. Get a simple explanation in your language.")

language = st.selectbox("Language", ["Hindi", "Tamil", "Bengali", "Marathi", "Telugu", "Kannada"])
image = st.file_uploader("Screenshot of the message", type=["png", "jpg", "jpeg"])
message = st.text_area("...or paste the text", height=120)

if st.button("Explain") and (message.strip() or image):
    if image:
        st.image(image, width=300)
    with st.spinner("Reading the message..."):
        try:
            st.write(explain(message, language, image.getvalue() if image else None))
        except Exception as e:
            st.error(f"Could not reach the model. Is Ollama running? ({e})")