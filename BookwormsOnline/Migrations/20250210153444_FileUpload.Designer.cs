﻿// <auto-generated />
using System;
using BookwormsOnline;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace BookwormsOnline.Migrations
{
    [DbContext(typeof(MyDbContext))]
    [Migration("20250210153444_FileUpload")]
    partial class FileUpload
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "8.0.8")
                .HasAnnotation("Relational:MaxIdentifierLength", 64);

            modelBuilder.Entity("BookwormsOnline.Models.User", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("char(36)");

                    b.Property<string>("BillingAddress")
                        .IsRequired()
                        .HasMaxLength(250)
                        .HasColumnType("varchar(250)");

                    b.Property<string>("CreditCardNo")
                        .IsRequired()
                        .HasColumnType("longtext");

                    b.Property<string>("Email")
                        .IsRequired()
                        .HasColumnType("longtext");

                    b.Property<int>("FailedLoginAttempts")
                        .HasColumnType("int");

                    b.Property<string>("FilePath")
                        .IsRequired()
                        .HasColumnType("longtext");

                    b.Property<string>("FirstName")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("varchar(100)");

                    b.Property<string>("LastName")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("varchar(100)");

                    b.Property<DateTime?>("LockoutEnd")
                        .HasColumnType("datetime(6)");

                    b.Property<string>("MobileNo")
                        .IsRequired()
                        .HasColumnType("longtext");

                    b.Property<string>("Password")
                        .IsRequired()
                        .HasColumnType("longtext");

                    b.Property<DateTime?>("PasswordExpires")
                        .HasColumnType("datetime(6)");

                    b.Property<DateTime>("PasswordLastChanged")
                        .HasColumnType("datetime(6)");

                    b.Property<string>("PasswordResetToken")
                        .IsRequired()
                        .HasColumnType("longtext");

                    b.Property<DateTime?>("PasswordResetTokenExpiry")
                        .HasColumnType("datetime(6)");

                    b.Property<string>("PreviousPasswordHash1")
                        .IsRequired()
                        .HasColumnType("longtext");

                    b.Property<string>("PreviousPasswordHash2")
                        .IsRequired()
                        .HasColumnType("longtext");

                    b.Property<string>("ShippingAddress")
                        .IsRequired()
                        .HasMaxLength(250)
                        .HasColumnType("varchar(250)");

                    b.HasKey("Id");

                    b.ToTable("Users");
                });
#pragma warning restore 612, 618
        }
    }
}
