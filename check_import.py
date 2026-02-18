try:
    import kivy_gradient
    print(f"kivy_gradient found: {kivy_gradient}")
    print(f"Dir: {dir(kivy_gradient)}")
    from kivy_gradient import Gradient
    print("Direct import successful")
except Exception as e:
    print(f"Import failed: {e}")
