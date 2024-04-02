import { Column, Entity, ManyToOne, ObjectId, ObjectIdColumn, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { Types } from "mongoose"
import { Exclude } from 'class-transformer';
import Role from '../enum/role.enum';


@Entity('Usingz')
class User {
    @ObjectIdColumn()
id: number;
 
  @Column({ unique: true })
  public email: string;
 
  @Column()
  public name: string;
 
  @Column()
  //@Exclude()
  public password: string;
  @Column()
  //@Exclude()
  public address: string;

  //uncomment line 20 and 21
//   @Column()
//  public refreshToken:string; 
  @Column({
    nullable: true
  })
  @Exclude()
  public currentHashedRefreshToken?: string;

  @Column({ default: false })
  public isRegisteredWithGoogle: boolean;

  @Column({ default: false })
  public isEmailConfirmed: boolean;
  //for the role management
  @Column({
    type: 'enum',
    enum: Role,
    array: true,
    default: [Role.User]
  })
  public roles: Role[]


  // @OneToMany((_type) => Task, (task) => task.user, { eager: true })
  // tasks: Task[];

  // @OneToMany(type=>ComplaintResolution,(complaint)=>complaint.user,{eager:true})
  // complaints:ComplaintResolution[];
}
 
export default User;