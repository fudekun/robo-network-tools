import { ComponentFixture, TestBed, waitForAsync } from '@angular/core/testing';

import { EmptyDialogComponent } from './empty-dialog.component';

describe('EmptyDialogComponent', () => {
  let component: EmptyDialogComponent;
  let fixture: ComponentFixture<EmptyDialogComponent>;

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      declarations: [ EmptyDialogComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(EmptyDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
