import sqlite3


def update_user(mode, session, bool):
    username = session['username']
    name = session['name']
    if "siren" in session:
        siren = session['siren']
    else:
        siren = None
    list = user_list(mode)
    if bool:
        if not(username in list):
            return add_user(mode, username, name, siren)
        else:
            return "User already in database"
    else:
        if username in list:
            return remove_user(mode, username)


def remove_user(mode, username) :
    """ Remove user"""
    path = mode.db_path
    conn = sqlite3.connect(path + 'directory.db')
    c = conn.cursor()
    data = {'username' : username}
    try :
        c.execute("DELETE FROM directory WHERE username = :username " , data)
        execution  = True
    except sqlite3.OperationalError :
        execution = False
    conn.commit()
    conn.close()
    return execution

def user_list(mode) :
    """ Return list of username """
    path = mode.db_path
    conn = sqlite3.connect(path + 'directory.db')
    c = conn.cursor()
    c.execute("SELECT username FROM directory")
    select = c.fetchall()
    conn.close()
    my_list = [item[0] for item in select if item[0] != '']
    my_list.sort()
    return my_list

def user_list_complete(mode) :
    """ Return list of username, name """
    path = mode.db_path
    conn = sqlite3.connect(path + 'directory.db')
    c = conn.cursor()
    c.execute("SELECT username, name FROM directory")
    select = c.fetchall()
    conn.close()
    my_list = []
    for item in select:
        user = dict()
        user['username'] = item[0]
        user['name'] = item[1]
        my_list.append(user)
    return my_list

def user_list_search(query, mode) :
    """ Return list of username, name """
    path = mode.db_path
    conn = sqlite3.connect(path + 'directory.db')
    c = conn.cursor()
    data = {'query' : '%' + query + '%'}
    c.execute("SELECT username, name FROM directory WHERE username LIKE :query OR name LIKE :query " , data)
    select = c.fetchall()
    conn.close()
    my_list = []
    for item in select:
        user = dict()
        user['username'] = item[0]
        user['name'] = item[1]
        my_list.append(user)
    return my_list

def search_siren(siren, mode) :
    """ Return list of username, name """
    path = mode.db_path
    conn = sqlite3.connect(path + 'directory.db')
    c = conn.cursor()
    data = {'siren' : siren}
    c.execute("SELECT username FROM directory WHERE siren = :siren" , data)
    select = c.fetchone()
    if not select :
        result = None
    else :
        result = select[0]
    conn.close()
    return result


def update_siren(username, new_siren, mode) :
	path = mode.db_path
	conn = sqlite3.connect(path + 'directory.db')
	cur = conn.cursor()
	data = { 'username' : username, 'siren' : new_siren}
	cur.execute("update directory set siren = :siren where username = :username", data )
	conn.commit()
	conn.close()


def add_user(mode, username, name, siren):
    """ Add user"""
    path = mode.db_path
    conn = sqlite3.connect(path + 'directory.db')
    c = conn.cursor()
    data = {'username' : username, 'name' : name, 'siren' : siren}
    try :
        c.execute("INSERT INTO directory(name,username,siren) VALUES (:name, :username, :siren)", data)
        execution  = True
    except sqlite3.OperationalError :
        execution = False
    conn.commit()
    conn.close()
    return execution

def search_user(mode, session):
    username = session['username']
    name = session['name']
    list = user_list(mode)
    return username in list
