import streamlit as st
import pandas as pd 
from checker import check_password, generate_password

st.set_page_config(
    page_title="Password Strength Checker",
    page_icon="🔐"
)

st.title("🔐 Password Strength Checker")
st.write("Check your password strength easily.")

password = st.text_input(
    "Enter a password",
    type="password"
)

if st.button("Check Password"):
    if password:
        result = check_password(password)

        st.subheader("Password Strength")
        st.success(result.label)
        st.progress(result.score / 100)

        st.write(f"Score: {result.score}/100")
        st.write(f"Length: {result.length} characters")
        st.write(f"Estimated entropy: {result.entropy_bits} bits")
        st.write(f"Estimated cracking time: {result.crack_time}")

        st.subheader("Character Types")
        st.write(f"Lowercase: {'Yes' if result.has_lower else 'No'}")
        st.write(f"Uppercase: {'Yes' if result.has_upper else 'No'}")
        st.write(f"Numbers: {'Yes' if result.has_digit else 'No'}")
        st.write(f"Symbols: {'Yes' if result.has_symbol else 'No'}")

        if result.issues:
            st.subheader("Problems Found")
            for issue in result.issues:
                st.write("- " + issue)

        if result.suggestions:
            st.subheader("Suggestions")
            for suggestion in result.suggestions:
                st.write("- " + suggestion)
    else:
        st.warning("Please enter a password.")

st.divider()

st.subheader("🎲 Generate a Strong Password")

length = st.slider("Password length", 8, 32, 16)
use_symbols = st.checkbox("Include symbols", value=True)

if st.button("Generate Password"):
    new_password = generate_password(
        length=length,
        use_symbols=use_symbols
    )
    st.code(new_password)
