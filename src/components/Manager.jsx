import React, { useRef, useState, useEffect } from "react";
import { ToastContainer, toast } from "react-toastify";
import { v4 as uuidv4 } from "uuid";
import passwordRules from "./variables.json";
import "react-toastify/dist/ReactToastify.css";
import axios from "axios";

const Manager = () => {
  const ref = useRef();
  const passwordRef = useRef();
  const [form, setForm] = useState({
    id: "",
    site: "",
    username: "",
    password: "",
  });
  const [passwordArray, setPasswordArray] = useState([]);
  const [passwordErrors, setPasswordErrors] = useState([]);
  const [isTyping, setIsTyping] = useState(false);

  const getPasswords = async () => {
    try {
      const response = await fetch(`${import.meta.env.VITE_REACT_APP_BACKEND_BASE_URL}`);
      const data = await response.json();

      setPasswordArray(
        data.map((pwd) => ({
          ...pwd,
          id: pwd._id,
          decryptedPassword: pwd.password || "", 
        }))
      );
    } catch (error) {
      console.error("Error fetching passwords:", error);
      toast.error("Failed to fetch passwords");
    }
  };

  const getFavicon = (domain) => {
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=25`;
  };

  useEffect(() => {
    getPasswords();
  }, []);

  const copyText = (text) => {
    toast("Copied to clipboard!", {
      position: "top-right",
      autoClose: 5000,
      hideProgressBar: false,
      closeOnClick: true,
      pauseOnHover: true,
      draggable: true,
      progress: undefined,
      theme: "dark",
    });
    navigator.clipboard.writeText(text);
  };

  const showPassword = () => {
    passwordRef.current.type =
      passwordRef.current.type === "password" ? "text" : "password";
    ref.current.src =
      passwordRef.current.type === "password"
        ? "icons/eye.png"
        : "icons/eyecross.png";
  };

  /*const checkURL = async (url) => {
    try {
      const response = await axios.get(url);
      if (response.status === 200) {
        setStatus("URL is responding properly.");
      } else {
        setStatus(`Received status code: ${response.status}`);
      }
    } catch (error) {
      setStatus(`Error: ${error.message}`);
    }
  };
  console.log(form.site);
  
  checkURL(form.site);
*/
  const generatePassword = () => {
    const lowerCase = "abcdefghijklmnopqrstuvwxyz";
    const upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_+[]{}|;:,.<>?";

    const allChars = lowerCase + upperCase + numbers + symbols;
    let generatedPassword = "";

    for (let i = 0; i < 12; i++) {
      const randomChar = allChars[Math.floor(Math.random() * allChars.length)];
      generatedPassword += randomChar;
    }
    setForm((prevForm) => ({ ...prevForm, password: generatedPassword }));
  };

  const validate = async (url) => {
    const ok = await axios.get(url);
    if (ok.status === 200) {
      return 1;
    }
  };
  const validatePassword = (password) => {
    const errors = Object.keys(passwordRules)
      .map((rule) => {
        const isValid = eval(passwordRules[rule].validate);
        return isValid ? null : passwordRules[rule].message;
      })
      .filter(Boolean);
    setPasswordErrors(errors);

    return errors.length === 0;
  };

  const savePassword = async () => {
    if (
      form.site.length > 3 &&
      form.username.length >= 3 &&
      validatePassword(form.password) &&
      validate(form.site)
    ) {
      try {
        if (form.id) {
          
        } else {
          const response = await fetch(`${import.meta.env.VITE_REACT_APP_BACKEND_BASE_URL}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              site: form.site,
              username: form.username,
              password: form.password,
            }),
          });

          if (!response.ok) {
            throw new Error("Failed to save password");
          }

          const data = await response.json();
          await getPasswords();
        }

        setForm({ id: "", site: "", username: "", password: "" });
        toast("Password saved!", {
          position: "top-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
          progress: undefined,
          theme: "dark",
        });
      } catch (error) {
        console.error("Error saving password:", error);
        toast.error("Failed to save password");
      }
    } else {
      toast.error(
        "Error: Password not saved! Ensure the password meets all criteria."
      );
    }
  };
  const deletePassword = async (id) => {
    const confirmDelete = confirm(
      "Do you really want to delete this password?"
    );

    if (confirmDelete) {
      try {
        // Send DELETE request to the server
        const response = await fetch(`${import.meta.env.VITE_REACT_APP_BACKEND_BASE_URL}/${id}`, {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || "Failed to delete password");
        }

        // Remove the deleted password from the state
        setPasswordArray(passwordArray.filter((item) => item._id !== id));

        // Show success message
        toast("Password Deleted!", {
          position: "top-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: true,
          draggable: true,
          progress: undefined,
          theme: "dark",
        });
      } catch (error) {
        // Handle errors (e.g., network issues, server errors)
        console.error("Error deleting password:", error);
        toast.error(`Error: ${error.message}`, {
          position: "top-right",
          autoClose: 5000,
          hideProgressBar: false,
          closeOnClick: true,
          draggable: true,
          progress: undefined,
          theme: "dark",
        });
      }
    }
  };
  const editPassword = (id) => {
    const passwordToEdit = passwordArray.find((item) => item.id === id);
    setForm({ ...passwordToEdit });
  };

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
    if (e.target.name === "password") {
      validatePassword(e.target.value);
      setIsTyping(e.target.value.length > 0);
    }
  };

  const renderPasswordTable = () => (
    <div className="overflow-x-auto">
      <table className="table-auto w-full rounded-md overflow-hidden mb-10">
        <thead className="bg-green-800 text-white">
          <tr>
            <th className="py-2">Site</th>
            <th className="py-2">Username</th>
            <th className="py-2">Password</th>
            <th className="py-2">Actions</th>
          </tr>
        </thead>
        <tbody className="bg-green-100">
          {passwordArray.map((item, index) => (
            <tr key={item._id || index}>
              <td className="py-2 border border-white text-center">
                <div className="flex items-center justify-center">
                  <img src={getFavicon(item.site)} className="mr-3" alt="" />
                  <a href={item.site} target="_blank" rel="noopener noreferrer">
                    {item.site}
                  </a>
                  <div
                    className="lordiconcopy size-7 cursor-pointer"
                    onClick={() => copyText(item.site)}
                  >
                    <lord-icon
                      style={{
                        width: "25px",
                        height: "25px",
                        paddingTop: "3px",
                        paddingLeft: "3px",
                      }}
                      src="https://cdn.lordicon.com/iykgtsbt.json"
                      trigger="hover"
                    ></lord-icon>
                  </div>
                </div>
              </td>
              <td className="py-2 border border-white text-center">
                <div className="flex items-center justify-center">
                  <span>{item.username}</span>
                  <div
                    className="lordiconcopy size-7 cursor-pointer"
                    onClick={() => copyText(item.username)}
                  >
                    <lord-icon
                      style={{
                        width: "25px",
                        height: "25px",
                        paddingTop: "3px",
                        paddingLeft: "3px",
                      }}
                      src="https://cdn.lordicon.com/iykgtsbt.json"
                      trigger="hover"
                    ></lord-icon>
                  </div>
                </div>
              </td>
              <td className="py-2 border border-white text-center">
                <div className="flex items-center justify-center">
                  <span>{"*".repeat(8)}</span>
                  <div
                    className="lordiconcopy size-7 cursor-pointer"
                    onClick={() => {
                      if (
                        item.decryptedPassword &&
                        item.decryptedPassword.length > 0
                      ) {
                        copyText(item.decryptedPassword);
                      } else {
                        toast.error("Password not available");
                      }
                    }}
                  >
                    <lord-icon
                      style={{
                        width: "25px",
                        height: "25px",
                        paddingTop: "3px",
                        paddingLeft: "3px",
                      }}
                      src="https://cdn.lordicon.com/iykgtsbt.json"
                      trigger="hover"
                    ></lord-icon>
                  </div>
                </div>
              </td>
              <td className="justify-center py-2 border border-white text-center">
                <span
                  className="cursor-pointer mx-1"
                  onClick={() => editPassword(item._id)}
                >
                  <lord-icon
                    src="https://cdn.lordicon.com/gwlusjdu.json"
                    trigger="hover"
                    style={{ width: "25px", height: "25px" }}
                  ></lord-icon>
                </span>
                <span
                  className="cursor-pointer mx-1"
                  onClick={() => deletePassword(item._id)}
                >
                  <lord-icon
                    src="https://cdn.lordicon.com/skkahier.json"
                    trigger="hover"
                    style={{ width: "25px", height: "25px" }}
                  ></lord-icon>
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  return (
    <>
      <ToastContainer />
      <div className="absolute inset-0 -z-10 h-full w-full bg-green-50 bg-[linear-gradient(to_right,#8080800a_1px,transparent_1px),linear-gradient(to_bottom,#8080800a_1px,transparent_1px)] bg-[size:14px_24px]">
        <div className="absolute left-0 right-0 top-0 -z-10 m-auto h-[310px] w-[310px] rounded-full bg-green-400 opacity-20 blur-[100px]"></div>
      </div>
      <div className="p-3 md:mycontainer min-h-[88.2vh]">
        <h1 className="text-4xl font-bold text-center">
          <span className="text-green-800">&lt;</span>
          <span>Hash</span>
          <span className="text-green-800">Vault/&gt;</span>
        </h1>
        <p className="text-green-900 text-lg text-center">
          Your own Password Manager
        </p>

        <div className="flex flex-col p-4 text-black gap-8 items-center">
          <input
            value={form.site}
            onChange={handleChange}
            placeholder="Enter website URL"
            className="rounded-full border border-green-500 w-full p-4 py-1"
            type="text"
            name="site"
            id="site"
          />
          <div className="flex flex-col md:flex-row w-full justify-between gap-8">
            <input
              value={form.username}
              onChange={handleChange}
              placeholder="Enter Username"
              className="rounded-full border border-green-500 w-full p-4 py-1"
              type="text"
              name="username"
              id="username"
            />
            <div className="flex flex-col relative">
              <div className="relative">
                <input
                  ref={passwordRef}
                  value={form.password}
                  onChange={handleChange}
                  onBlur={() => setIsTyping(false)}
                  placeholder="Enter Password"
                  className="rounded-full border border-green-500 w-full p-4 py-1"
                  type="password"
                  name="password"
                  id="password"
                />
                <span
                  className="absolute right-[3px] top-[4px] cursor-pointer"
                  onClick={showPassword}
                >
                  <img
                    ref={ref}
                    className="p-1"
                    width={26}
                    src="icons/eye.png"
                    alt="eye"
                  />
                </span>
              </div>
              {isTyping && (
                <div className="flex flex-col items-start w-full absolute top-10">
                  <div className="mt-2 p-2 border rounded bg-gray-100">
                    <ul>
                      <li
                        style={{
                          color: form.password.length >= 8 ? "green" : "red",
                        }}
                      >
                        8-20 Characters
                      </li>
                      <li
                        style={{
                          color: /[A-Z]/.test(form.password) ? "green" : "red",
                        }}
                      >
                        At least one capital letter
                      </li>
                      <li
                        style={{
                          color: /\d/.test(form.password) ? "green" : "red",
                        }}
                      >
                        At least one number
                      </li>
                      <li
                        style={{
                          color: !/\s/.test(form.password) ? "green" : "red",
                        }}
                      >
                        No spaces
                      </li>
                      <li
                        style={{
                          color: /[!@#$%^&*(),.?\\":{}|<>]/.test(form.password)
                            ? "green"
                            : "red",
                        }}
                      >
                        Password must contain at least one special character
                      </li>
                    </ul>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Add a button to generate a password */}
          <button
            onClick={generatePassword}
            className="bg-green-600 hover:bg-green-600 text-white rounded-full px-4 py-2"
          >
            Generate Password
          </button>

          <button
            onClick={savePassword}
            className="flex justify-center items-center gap-2 bg-green-500 hover:bg-green-600 rounded-full px-8 py-2 w-fit border border-green-900"
          >
            <lord-icon
              src="https://cdn.lordicon.com/jgnvfzqg.json"
              trigger="hover"
            ></lord-icon>
            {form.id ? "Update" : "Save"}
          </button>
        </div>
        <div className="passwords">
          <h2 className="font-bold text-2xl py-4">Your Passwords</h2>
          {passwordArray.length === 0 && <div>No passwords to show</div>}
          {passwordArray.length !== 0 && renderPasswordTable()}
        </div>
      </div>
    </>
  );
};

export default Manager;
