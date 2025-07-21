from locust import FastHttpUser, task, between, tag

class WebsiteUser(FastHttpUser):
    wait_time = between(2.5,2.6)
    #between(1, 5)
    
    @task
    @tag('16K')
    def test_16K(self):
        self.client.get("/lorem-16K.html")
    
    @task
    @tag('32K')
    def test_32K(self):
        self.client.get("/lorem-32K.html")
    
    @task
    @tag('64K')
    def test_64K(self):
        self.client.get("/lorem-64K.html")
    
    @task
    @tag('128K')
    def test_128K(self):
        self.client.get("/lorem-128K.html")
    
    @task
    @tag('256K')
    def test_256K(self):
        self.client.get("/lorem-256K.html")