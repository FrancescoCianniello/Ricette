//Function for registration management
document.getElementById('registerForm')?.addEventListener('submit', async (e) => {
    e.preventDefault(); //Prevents form submission
//Retrieve the data entered by the user
    const name = document.getElementById('name').value;
    const surname = document.getElementById('surname').value;
    const fiscal_code = document.getElementById('fiscal_code').value;
    const date_of_birth = document.getElementById('date_of_birth').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const message = document.getElementById('message'); //Display of messages

    try {
        //Send a POST request to the server for registration
        const response = await fetch('http://127.0.0.1:5000/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, surname, fiscal_code, date_of_birth, username, password}) //Request in json format
        });

        const result = await response.json(); // JSON response parse
        if (response.ok) {
            message.textContent = "Registration completed! Go to login";
            message.style.color = 'green';
        } else {
            message.textContent = result.error;
            message.style.color = 'red';
        }
    } catch (error) {
        message.textContent = 'Error connecting to the server';
        message.style.color = 'red';
    }
});

//Function for login management
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault(); //Prevents form submission
//Retrieve the data entered by the user
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const message = document.getElementById('message');

    try {
        //Send a POST request to the server for login
        const response = await fetch('http://127.0.0.1:5000/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password}) //Request in json format
        });

        const result = await response.json(); // JSON response parse
        if (response.ok) {
            //  Saving the JWT token to localStorage
            localStorage.setItem('token', result.access_token);
            message.textContent = "Login successfully!";
            message.style.color = 'green';
            setTimeout(() => window.location.href = 'welcome.html', 500); //Redirect set after 0.5 seconds
        } else {
            message.textContent = result.error;
            message.style.color = 'red';
        }
    } catch (error) {
        message.textContent = 'Error connecting to the server';
        message.style.color = 'red';
    }
});

// Function for managing page security
if (document.getElementById('welcomeMessage')) {
    // JWT token recovery
    const token = localStorage.getItem('token');

    if (!token) {
        window.location.href = 'login.html'; //Redirect to log in if the token does not exist
    } else {
        fetch('http://127.0.0.1:5000/protected', {
            method: 'GET',
            headers: {'Authorization': `Bearer ${token}`} //Include the token in the header
        })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    document.getElementById('welcomeMessage').textContent = data.message; //Show a welcome message
                } else {
                    localStorage.removeItem('token');
                    window.location.href = 'login.html'; //Redirect to log in
                }
            })
            .catch(() => {
                localStorage.removeItem('token');
                window.location.href = 'login.html'; //Redirect to log in
            });
    }
}

//Logout function
function logout() {
    localStorage.removeItem('token');
    window.location.href = 'login.html'; //Redirect to log in
}