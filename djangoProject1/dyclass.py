# 定义一个动态类的方法
def say_hello(self):
    print(f"Hello, I am {self.name}")

# 使用type()创建一个动态类
Person = type("Person", (object,), {"name": "John Doe", "say_hello": say_hello})

# 创建一个Person类的实例
person = Person()

# 调用say_hello方法
person.say_hello()
