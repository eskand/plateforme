import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators} from '@angular/forms';
import { Router } from '@angular/router';
import { User } from '../classes/user';
import { MustMatch } from '../_helpers/must-match.validator';
import { AuthService } from '../_services/auth.service';

// import custom validator to validate that password and confirm password fields match
@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
    display = 'none';
  modalObject = {};
    loading = false;
  registerForm!: FormGroup;
  submitted = false;
    msg: any;
    user=new User();
  constructor(private formBuilder: FormBuilder,private _service:AuthService, private _router :Router) { }

  ngOnInit() {
      this.registerForm = this.formBuilder.group({
          title: ['', Validators.required],
          firstName: ['test', Validators.required],
          lastName: ['', Validators.required],
          email: ['', [Validators.required, Validators.email]],
          password: ['', [Validators.required, Validators.minLength(6)]],
          confirmPassword: ['', Validators.required],
          acceptTerms: [false, Validators.requiredTrue]
      }, {
          validator: MustMatch('password', 'confirmPassword')
      });
      this.modalObject = {
        title: "",
        body: ""
      }
  }

  // convenience getter for easy access to form fields
  get f() { return this.registerForm.controls; }

  onSubmit() {
    
      this.submitted = true;

      // stop here if form is invalid
      if (this.registerForm.invalid) {
          return;
      }
      
      this._service.register(this.user).subscribe(
        data=>{
          console.log("response received");
          this.showModal();
          this._router.navigate(['/login'])
        },
        error=>{
          console.log("exception occured");
          this.msg=error.error;
          this.loading = false;
        }
      )

      // display form values on success
      alert('SUCCESS!! :-)\n\n' + JSON.stringify(this.registerForm.value, null, 4));
  }
  displayChange(value:any) {
    this.display = 'none'
  }
  onReset() {
      this.submitted = false;
      this.registerForm.reset();
  }

  showModal() {
    this.display = 'block';
    this.modalObject = {
      title: "SignUp Successful",
      body: `Thanks for signing in!. 
            Account verification link is sent on your mail id 
            ${this.registerForm.value.email}. 
            Click on link to activate your account.`
    }

}
}

