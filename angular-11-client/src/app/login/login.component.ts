import { Component, OnInit } from '@angular/core';
import { AuthService } from '../_services/auth.service';
import { TokenStorageService } from '../_services/token-storage.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  rememberMe: boolean = false;
  display = 'none'
  verifyModalData = {}
  form: any = {
    email: null,
    password: null
  };
  isLoggedIn = false;
  isLoginFailed = false;
  errorMessage = '';
  roles: string[] = [];

  constructor(private authService: AuthService, private tokenStorage: TokenStorageService) { }

  ngOnInit(): void {
    if (this.tokenStorage.getToken()) {
      this.isLoggedIn = true;
      this.roles = this.tokenStorage.getUser().roles;
    }
  }

  onSubmit(): void {
    const { email, password } = this.form;

    this.authService.login(email, password).subscribe(
      data => {
        this.tokenStorage.saveToken(data.accessToken);
        this.tokenStorage.saveUser(data);

        this.isLoginFailed = false;
        this.isLoggedIn = true;
        this.roles = this.tokenStorage.getUser().roles;
        this.reloadPage();
        this.saveCredentials();
      },
      err => {
        this.errorMessage = err.error.message;
        this.isLoginFailed = true;
      }
    );
  }
  saveCredentials() {
    if(this.rememberMe) {
      (      data: { accessToken: string; }) => {
        this.tokenStorage.saveToken(data.accessToken);
        this.tokenStorage.saveUser(data);
    
      this.roles = this.tokenStorage.getUser().roles;
    }
  }}
  toggleValue(event:any) {
    if(event.target.checked) {
      this.rememberMe = true;
    }
  }

  reloadPage(): void {
    window.location.reload();
  }
  openForgotPassModal() {
    this.setVerifyModalData('Reset Password', 'Send OTP', 'reset');
    this.display = 'block';
  }
  openVerifyEmailModal() {
    this.setVerifyModalData('Verify email', 'Send link', 'verify');
    this.display = 'block';
  }
  setVerifyModalData(title:string = '', btn: string = '', type: string = '') {
    this.verifyModalData = {
      title: title,
      btn: btn,
      type: type
    }
}}
