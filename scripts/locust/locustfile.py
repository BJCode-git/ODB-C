from locust import FastHttpUser, task, between

class WebsiteUser(FastHttpUser):
    wait_time = between(2.5,2.6)
    #between(1, 5)
    
    @task(1)    
    def test_jpg(self):
        self.client.get("/test.jpg")
        
    @task(2)    
    def test_jpg(self):
        self.client.get("/test4.jpg")
    
    @task(3)
    def test_lorem(self):
        self.client.get("/lorem.html")
    
    #@task
    #def index(self):
    #    self.client.get("/index.html")
    #
    #@task(1)
    #def test_lorem(self):
    #    self.client.get("/lorem.html")
    #    
    #@task(2)
    #def test_png(self):
    #    self.client.get("/qr-code.png")
    #
    #@task(2)
    #def test_jpg(self):
    #    self.client.get("/test1.jpg")
    #    
    #@task(2)
    #def test2_jpg(self):
    #    self.client.get("/test2.jpg")
    #    
    #@task(2)
    #def test3_jpg(self):
    #    self.client.get("/test3.jpg")
    #    
    #@task(3)
    #def test1_mp4(self):
    #    self.client.get("/test.mp4")
    #    
    #@task(3)
    #def test2_mp4(self):
    #    self.client.get("/vid.mp4")
        
    
        
