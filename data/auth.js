let users = [
    {
        id:'1',
        username:'apple',
        password:'1111',
        name:'김사과',
        email:'apple@apple.com',
        url:'https://png.pngtree.com/thumb_back/fh260/background/20230611/pngtree-woman-s-face-with-long-brown-eyes-image_2888808.jpg'
    },
    {
        id:'2',
        username:'banana',
        password:'2222',
        name:'반하나',
        email:'banana@banana.com',
        url:'https://png.pngtree.com/thumb_back/fh260/background/20230611/pngtree-woman-s-face-with-long-brown-eyes-image_2888808.jpg'
    },
    {
        id:'3',
        username:'orange',
        password:'3333',
        name:'오렌지',
        email:'orange@orange.com',
        url:'https://png.pngtree.com/thumb_back/fh260/background/20230611/pngtree-woman-s-face-with-long-brown-eyes-image_2888808.jpg'
    }
]

export async function createUser(username, password, name, email){
    const user = {
        id:'4',
        username:username,
        password:password,
        name:name,
        email:email,
        url:'https://png.pngtree.com/thumb_back/fh260/background/20230611/pngtree-woman-s-face-with-long-brown-eyes-image_2888808.jpg'
    }
    users = [user, ...users]
    return user
}

export async function login(username){
    const user = users.find((user) => user.username === username)
    return user
}