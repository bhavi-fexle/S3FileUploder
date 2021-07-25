# S3FileUploder

# Deploy to heroku:

Login to heroku (One time):
```
heroku login
```

Connect repo to heroku (one time):
```
heroku create
heroku git:remote -a fineuploader
```

Commit the changes, and then use this command to deploy:
```
git push heroku main
```

View logs:
```
heroku logs -t
```