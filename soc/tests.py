from tasks import add


result = add.delay(2, 98)
print("Task result: ", result.get())


