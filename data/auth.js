let users = [
    {
        id:'1',
        username:'apple',
        password:'$2b$10$pgJ/lpeHhtG9cYGGgKq.U.9.iZ/hX1j.kgVp/qTpDembvr.0XhNKK',
        name:'김사과',
        email:'apple@apple.com',
        url:'https://png.pngtree.com/thumb_back/fh260/background/20230611/pngtree-woman-s-face-with-long-brown-eyes-image_2888808.jpg'
    },
    {
        id:'2',
        username:'banana',
        password:'$2b$10$klvYHmNBMvLJQbiRbYFCt.mj2li27XjsToNP9gHl.fYPDFOu.DTQK',
        name:'반하나',
        email:'banana@banana.com',
        url:'https://png.pngtree.com/thumb_back/fh260/background/20230611/pngtree-woman-s-face-with-long-brown-eyes-image_2888808.jpg'
    },
    {
        id:'3',
        username:'orange',
        password:'$2b$10$XHe2BZnunhm.53Dwwvx8.e7rtgrbu4viFE55uKLdpNYcgDXqDnUM2',
        name:'오렌지',
        email:'orange@orange.com',
        url:'https://png.pngtree.com/thumb_back/fh260/background/20230611/pngtree-woman-s-face-with-long-brown-eyes-image_2888808.jpg'
    }
]

export async function createUser(username, password, name, email){
    const user = {
        id:'4',
        username,
        password,
        name,
        email,
        url:'https://png.pngtree.com/thumb_back/fh260/background/20230611/pngtree-woman-s-face-with-long-brown-eyes-image_2888808.jpg'
    }
    users = [user, ...users]
    return user
}

export async function findByUsername(username){
    const user = users.find((user) => user.username === username)
    return user
}

export async function findById(id){
    return users.find((user) => user.id === id)
}