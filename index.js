const express=require("express");

const app=express()
app.set("view engine","ejs")

app.get("/",(req,res)=>{
    res.render("homepage",{title:"AcademiaPress"})

})

app.listen(3000,()=>{
    console.log("server fired up")
})

