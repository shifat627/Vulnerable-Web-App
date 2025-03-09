from flask import Flask,Response,redirect,render_template,request,url_for,send_from_directory,jsonify,send_file
import sqlite3,os,jwt,uuid,gnupg
from werkzeug.utils import secure_filename

import requests,tempfile

JWT_SECRET = 'fJfOBfIDW6peoNQIe5ba'

app = Flask(__name__)


UPLOAD_DIR = os.path.join(os.path.dirname(__file__),'uploaded_file')
GPG = os.path.join(UPLOAD_DIR,'gnupg')
if not os.path.exists(UPLOAD_DIR):
    os.mkdir(UPLOAD_DIR)
if not os.path.exists(GPG):
    os.mkdir(GPG)

gpg = gnupg.GPG(gnupghome=GPG)



def Login_required():
    token = request.cookies.get('SESSION',None)
        
    user = None
        
    if token:
        user = jwt.decode(token,JWT_SECRET,algorithms=['HS256'])
        #print(user)
        db = sqlite3.connect('Labdb.sqlite')
        #db.row_factory = sqlite3.Row
        cur = db.cursor()
        data = cur.execute("select user_id from loggedInUser where UID = ?",(user.get('uid',''),)).fetchone()
        #print(data)
        if data is not None:
            user['id'] = data[0]
            data = cur.execute("select username from users where id = ?",(data[0],)).fetchone()
            #print(data)
            if data[0] != user.get('username',''):
                user = None
            
                
        else:
            user = None

        db.close()

    return user
    
    
@app.route('/settings',methods=['GET','POST'])
def Settings():
    userInfo = Login_required()

    if userInfo is None:
        return redirect(url_for('Login'))
    
    if request.method == 'GET':
        return render_template('Settings.html',msg = '')
    if request.method == 'POST':
        email = request.form.get('email',None)
        password = request.form.get('password',None)
        name = request.form.get('name',None)
        
        if email and password and name:
            db = sqlite3.connect('Labdb.sqlite')
            db.row_factory = sqlite3.Row    
            cur = db.cursor()
            cur.execute("update users set email = ? , name = ? , password = ?  where username = ? ",(email,name,password,userInfo['username']))
            
            db.commit()
            db.close()
    
    return render_template('Settings.html',msg = 'Info is saved')


@app.route('/')
def Home():
    userInfo = Login_required()
    if userInfo:
        
        return render_template('Home.html',username = userInfo['username'])
    else:
        return redirect(url_for('Login'))


@app.route('/login',methods=['GET','POST'])
def Login():

    user = Login_required()
    
    if user is not None:
        return redirect(url_for('Home'))
    
    db = sqlite3.connect('Labdb.sqlite')
    db.row_factory = sqlite3.Row

    if request.method == 'GET':
        return render_template('Login.html')
    if request.method == 'POST':
        username = request.form.get('username',None)
        password = request.form.get('password',None)

        if username and password:
            cur = db.cursor()
            output_cur = cur.execute("select * from users where username = ? and password = ?",(username,password))
            data = output_cur.fetchone()
            
            
            if data is not None:
                if data['is_active'] == 0:
                    return Response('This account is not active',500)
                
                token_json = dict(data)
                
                del token_json['id']
                del token_json['password']

                user_uuid = str(uuid.uuid4())
                token_json['uid'] = user_uuid
                
                cur.execute("insert into loggedInUser (user_id,UID) values (? , ?)",(data['id'],user_uuid))
                db.commit()
                db.close()

                token = jwt.encode(token_json,JWT_SECRET,algorithm='HS256')

                res = redirect(url_for('Home'))
                res.set_cookie('SESSION',token)
                return res
            
            else:
                db.close()
                return redirect(url_for('Login'))
        else:
            db.close()
            return redirect(url_for('Login'))






@app.get('/logout')
def Logout():
    user = Login_required()
    if user is None:
        res = redirect(url_for('Login'))
        res.set_cookie('SESSION','',expires=0)
        return res
    
    db = sqlite3.connect('Labdb.sqlite')
    cur = db.cursor()
    cur.execute("DELETE from loggedInUser where UID = ?",(user['uid'],))
    db.commit()
    db.close()

    res = redirect(url_for('Login'))
    res.set_cookie('SESSION','',expires=0)
    return res









@app.route('/upload',methods=['GET','POST']) #Path Traversal
def Upload():
    user = Login_required()

    if user is None:
        return redirect(url_for('Login'))
    

    if request.method == 'POST':
        user_dir = os.path.join(UPLOAD_DIR,user['username'])
        if not os.path.exists(user_dir):
            os.mkdir(user_dir)
        
        request.files['file'].save(os.path.join(user_dir,request.files['file'].filename.replace('../','').replace('..\\',''))) # Broken Defence

        db = sqlite3.connect('Labdb.sqlite')
        cur = db.cursor()
        
        cur.execute("insert into FileList(user_id,filePath) values (? , ?)",(user['id'],secure_filename(request.files['file'].filename)))
        db.commit()
        db.close()

        return render_template('Upload.html',success = True)

    return render_template('Upload.html',success = False)




@app.route('/post',methods=['GET','POST']) #XSS
def Post():
    user = Login_required()

    if user is None:
        return redirect(url_for('Login'))
    

    if request.method == 'POST':
        content = request.form.get('content','Empty Post')

        db = sqlite3.connect('Labdb.sqlite')
        cur = db.cursor()
        
        #cur.execute("insert into Posts(user_id,post) values (? , ?)",(user['id'],content.replace('<','-').replace('>','-')))

        cur.execute("insert into Posts(user_id,post) values (? , ?)",(user['id'],content))
        db.commit()
        db.close()

        return render_template('Post.html',success = True)

    return render_template('Post.html',success = False)



@app.route('/users',methods=['GET']) #CORS
def UserList():
    user = Login_required()

    if user is None:
        return redirect(url_for('Login'))

    if user.get('is_admin',0) != 1:
        return Response('Forbidden',403)
    

    db = sqlite3.connect('Labdb.sqlite')
    db.row_factory = sqlite3.Row
    cur = db.cursor()
    
    data = cur.execute("select * from users").fetchall()
    db.commit()
    db.close()

    serialize = []
    for row in data:
        serialize.append(dict(row))
    
    
    res = jsonify(serialize)
    
    
    if 'testsite.com' in request.headers.get('Origin',''):
        res.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        res.headers['Access-Control-Allow-Credentials'] = True
    else:
        res.headers['Access-Control-Allow-Origin']='http://testsite.com'
        
    return res



@app.route('/getFile',methods=['GET']) #IDOR
def Download():
    user = Login_required()

    if user is None:
        return redirect(url_for('Login'))
    
    
    if request.args.get('id','') == '':
        db = sqlite3.connect('Labdb.sqlite')
        db.row_factory = sqlite3.Row
        cur = db.cursor()
        data = cur.execute("select * from FileList where user_id = ?",(user['id'],)).fetchall()
        db.close()

        return render_template ('Filemanager.html',files = data,is_admin = user['is_admin'])

    db = sqlite3.connect('Labdb.sqlite')
    db.row_factory = sqlite3.Row
    cur = db.cursor()
    
    
    data = cur.execute("select * from FileList where id = ?",(request.args.get('id',-1),)).fetchone()

    
    if data:
        path = data['filePath']
        data = cur.execute("select * from users where id = ?",(data['user_id'],)).fetchone()
        
        
    db.close()

    if data:
        try:
            user_dir = os.path.join(UPLOAD_DIR,data['username'])

            if os.path.exists(os.path.join(user_dir,'myPublic.key')):
                
                for key in gpg.list_keys():
                    gpg.delete_keys(key['fingerprint'])
                
                key = gpg.import_keys_file(os.path.join(user_dir,'myPublic.key'))
                # if key.count != 1:
                #     return Response('Too Many Keys',status=500)
                TemPath = os.path.join(tempfile.gettempdir(),path)+'.gpg'
                #print(key.fingerprints[0])
                with open(os.path.join(user_dir,path),'rb') as f:
                    data = gpg.encrypt_file(f,recipients=[key.fingerprints[0]],armor=True,output=TemPath,always_trust=True)
                    
                gpg.delete_keys(key.fingerprints[0])

                return send_file(TemPath)

            return send_from_directory(user_dir,path)
        except Exception as Err:
            return Response(str(Err),500)
    return Response(status=500)



@app.get('/notice')
def Notice():
    Total_posts = []

    db = sqlite3.connect('Labdb.sqlite')
    db.row_factory = sqlite3.Row
    cur = db.cursor()

    if request.args.get('author','') != '':
        user = cur.execute(f"select * from users where username = '{request.args['author'].replace(' ','').replace('    ','')}' ").fetchone()
        if user:
            posts = cur.execute(f"select * from Posts where user_id = {user['id']} ").fetchall()

            if posts:
                for post in posts:
                    Temp = dict(post)
                    Temp.update(dict(user))
                    Total_posts.append(Temp)
        
    else:
        users = cur.execute("select * from users").fetchall()
        
        if users:
            for user in users:
                user_posts = cur.execute("select * from Posts where user_id = ?",(user['id'],)).fetchall()
                
                if user_posts:
                    for post in user_posts:
                        Temp = dict(post)
                        Temp.update(dict(user))
                        Total_posts.append(Temp)
                        
                

    db.close()

    return render_template('Notice.html',news = Total_posts)






@app.get('/view')
def View():

    user = Login_required()

    if user is None:
        return redirect(url_for('Login'))
    
    if user['is_admin'] != 1:
        return Response('Forbidden',status=403)
    
    filename = request.args.get('file','')
    if filename:
        #print(filename.replace('../',''))
        root = os.path.join(UPLOAD_DIR,user['username'])
        return send_file(os.path.join(root,filename.replace('../','').replace('..\\','')))
    
    return Response(status=500)


@app.route('/proxy',methods = ['GET','POST'])
def Proxy():
    user = Login_required()

    if user is None:
        return redirect(url_for('Login'))
    
    if user['is_admin'] != 1:
        return Response('Forbidden',status=403)
    
    if request.method == 'GET':
        return render_template('Proxy.html')
    if request.method == 'POST':

        page = request.form.get('url','')
        for blacklist in ['localhost','127.0.0.1']:
            if blacklist in page:
                return Response('What are You Doing? Are You really Admin?',status=403)
        
        if page:
            req = requests.get(page,verify=False)
            if req.ok:
                return Response(req.content.decode(),200)

        return Response(status=500)

    

if __name__ == '__main__':
    app.run('0.0.0.0',80,True)
    