from AuthBarn import *

credential = ["127.0.0.1",3306,"root","Lionel12$","test"]
write_credentials_to_env(credential[0],credential[1],credential[2],credential[3],credential[4])
test = Action(enable_logging=True,dev_mode=True)

print(test.login("darell","12345"))



# token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VybmFtZSI6ImRkIiwiUm9sZSI6IlVzZXIiLCJQZXJtaXNzaW9uIjpbXX0.KZpGBUxfOOp2LoNKlpmbeawtZxKeKzeNEt03CzIoXXk"
# token_bytes = token.encode("utf-8")

# @test.require_permission("Admin")
# def prinny(token):
#     print("hello, world!")


# prinny(token_bytes)