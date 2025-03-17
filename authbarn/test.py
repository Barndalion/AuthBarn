def count(n):
    scene = {}
    once = []
    for i in n:
        if i not in scene:
            scene[i] = 1
        elif i in scene:
            scene[i] += 1

        
    for key, value in scene.items():
        if value == 1:
            once.append(key)
            return once

    
        
    
        
n= [1,2,3,4,5,2,3,5,24,3,235,4,32,2,4,2,1,1,1,1,5,3,2,4,6,3,5,3,2]
print(count(n))
