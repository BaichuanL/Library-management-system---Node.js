// 导入数据库操作模块
const db = require('../db/index')
const bcrypt = require('bcryptjs')
// 用这个包来生成 Token 字符串
const jwt = require('jsonwebtoken')
// 导入配置文件
const config = require('../config')



// 注册用户的处理函数
exports.regUser = (req, res) => {
    // 接收表单数据
    const userinfo = req.body
    // 判断数据是否合法
    if (!userinfo.username || !userinfo.password) {
       return res.send({ status: 1, message: '用户名或密码不能为空！' })
    }

    //定义 SQL 语句
    const sql = 'select * from ev_users where username=?'
    db.query(sql, [userinfo.username], function (err, results) {

        // 执行 SQL 语句失败
        if (err) {
          return res.cc(err)
        }

        // 用户名被占用
        if (results.length > 0) {
          return res.cc('用户名被占用，请更换其他用户名！')
        }

        // 对用户的密码,进行 bcrype 加密，返回值是加密之后的密码字符串
        userinfo.password = bcrypt.hashSync(userinfo.password, 10)

        //定义插入用户的 SQL 语句
        const sql = 'insert into ev_users set ?'
        db.query(sql, { username: userinfo.username, password: userinfo.password }, function (err, results) {

            // 执行 SQL 语句失败
            if (err) return res.cc(err)

            // SQL 语句执行成功，但影响行数不为 1
            if (results.affectedRows !== 1) {
              return res.cc('注册用户失败，请稍后再试！')
            }

            // 注册成功
            return res.cc('注册成功', 0)
          })          

      })
      
}
  
// 登录的处理函数
exports.login = (req, res) => {
  
  //接收表单数据
  const userinfo = req.body

  //定义 SQL 语句
  const sql = `select * from ev_users where username=?`

  //执行 SQL 语句，查询用户的数据
  db.query(sql, userinfo.username, function (err, results) {

    // 执行 SQL 语句失败
    if (err) return res.cc(err)

    // 执行 SQL 语句成功，但是查询到数据条数不等于 1
    if (results.length !== 1) return res.cc('登录失败！')

    // 拿着用户输入的密码,和数据库中存储的密码进行对比
    const compareResult = bcrypt.compareSync(userinfo.password, results[0].    password)
    
    // 如果对比的结果等于 false, 则证明用户输入的密码错误
    if (!compareResult) {
      return res.cc('登录失败！')
    }
    

    // Token
    // 剔除完毕之后，user 中只保留了用户的 id, username, nickname, email 这四个属性的值
    const user = { ...results[0], password: '', user_pic: '' }

    // 生成 Token 字符串
    const tokenStr = jwt.sign(user, config.jwtSecretKey, {
      expiresIn: config.expireIn,
    })

    // 将生成的 Token 字符串响应给客户端
    res.send({
      status: 0,
      message: '登录成功！',
      // 为了方便客户端使用 Token，在服务器端直接拼接上 Bearer 的前缀
      token: 'Bearer ' + tokenStr,
    })    

  })
  
}
  