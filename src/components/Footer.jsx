import React from "react";

const Footer = () => {
  return (
    <div className="bg-slate-800 text-white flex flex-col justify-center items-center  w-full">
      <div className="logo font-bold text-white text-2xl">
        <span className="text-green-600"> &lt;</span>
        <span>Hash</span>
        <span className="text-green-600">Vault/&gt;</span>
      </div>
      <div className="flex justify-center items-center">
        {" "}
        Created with <img
          className="w-7 mx-2"
          src="icons/heart.png"
          alt=""
        />{" "}
        by manoj{" "}
      </div>
    </div>
  );
};

export default Footer;
